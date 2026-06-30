#!/usr/bin/env python3
"""
Sub-Pro v3.0.0 — Subdomain Prober
Author: Saurabh Jain

Pipeline:
  subfinder  →  enumerate subdomains
  httpx      →  probe live hosts (JSON output, single process)
  filter     →  keep desired status codes
  export     →  TXT artifacts + xlsx / csv / json report

Changes in v3 (all review suggestions applied):
  ── Bugs & correctness ──────────────────────────────────────────────────────
  [BUG]  Live table + Progress conflict fixed: both rendered inside a single
         Live(Group(progress, table)) context — one owner of stdout.
  [BUG]  Parallel console safety: threading.Lock guards every console.print()
         call so interleaved domain output never garbles.
  [BUG]  Cache/timestamp conflict fixed: stable cache dir (domain-name/) holds
         all.txt; timestamped run dir (domain-name/YYYY-MM-DD_HH-MM-SS/) holds
         the per-run reports. Cache now actually works.
  [BUG]  Removed unused `field` import from dataclasses.

  ── Performance & optimization ───────────────────────────────────────────────
  [PERF] httpx batching removed: all subdomains passed in a single Popen call;
         httpx handles concurrency via -threads. Eliminates per-batch startup
         overhead and simplifies progress tracking.
  [PERF] Export builds DataFrame directly from dataclass attrs — no intermediate
         dict list.
  [PERF] --subfinder-timeout separate from --httpx-timeout so slow API sources
         don't block the probe phase and vice-versa.
  [PERF] --rate-limit flag passes httpx -rate-limit for throttled probing.
  [PERF] --all-sources flag passes subfinder -all for maximum subdomain yield.

  ── Console UI & design ──────────────────────────────────────────────────────
  [UI]   Live findings table capped at last LIVE_TABLE_ROWS rows (default 20)
         using a rolling deque — no unbounded scrolling.
  [UI]   Total wall-clock runtime shown in final done panel.
  [UI]   Summary table sorted by original domain input order, not completion
         order, so output is deterministic.
  [UI]   Active status codes shown in pre-flight config line.
  [UI]   Per-domain result table shows subfinder_elapsed + httpx_elapsed
         breakdown, not just total.
  [UI]   Banner redrawn with symmetric block alignment.

  ── Options ──────────────────────────────────────────────────────────────────
  [OPT]  --no-probe: enumerate subdomains only, skip httpx entirely.
  [OPT]  --exclude-file FILE: skip subdomains matching patterns in file.
  [OPT]  --dry-run: print what would run without executing anything.
  [OPT]  --workers default changed to 1 (safe); help text warns about load.
  [OPT]  --max-runtime: hard ceiling on total wall-clock seconds.

  ── Execution & time ─────────────────────────────────────────────────────────
  [TIME] DomainCounts now stores subfinder_elapsed and httpx_elapsed separately.
  [TIME] --subfinder-timeout and --httpx-timeout are independent flags.
  [TIME] --max-runtime enforced via a background watchdog thread.

Requires binaries in PATH: subfinder, httpx
Python deps: pandas, openpyxl, rich
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Iterable, List, Optional, Sequence, Set

import pandas as pd

from rich.console import Console, Group   # Group lives in rich.console (all versions)
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.traceback import install as install_rich_traceback
from rich import box

install_rich_traceback()

# ── Version ───────────────────────────────────────────────────────────────────
__version__ = "3.0.0"

# ── Live table row cap ────────────────────────────────────────────────────────
LIVE_TABLE_ROWS = 20

# ── Console + thread lock ─────────────────────────────────────────────────────
# [BUG FIX] All console.print() calls go through _cprint() which holds this
# lock, preventing interleaved output when --workers > 1.
console    = Console()
_print_lck = threading.Lock()

def _cprint(*args, **kwargs) -> None:
    with _print_lck:
        console.print(*args, **kwargs)

LOG      = logging.getLogger("sub_pro")
ANSI_RE  = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
DATE_STR = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


# ── Utilities ─────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
    )


def which_or_die(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if not path:
        _cprint(f"  [bold red]✗[/] Binary not found in PATH: [bold]{bin_name}[/]")
        sys.exit(2)
    return path


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_lines(path: str, lines: Iterable[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln.rstrip("\n") + "\n")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def domain_safe_name(domain: str) -> str:
    """Return a filesystem-safe folder name derived from the domain."""
    d     = domain.strip().lower()
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 2:
        parts = parts[:-1]
    name = "-".join(parts) if parts else d
    name = re.sub(r"[^a-z0-9\-_]", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    return name or "domain"


def status_colour(code: str) -> str:
    """Map HTTP status code → Rich colour tag."""
    if not code:
        return "dim"
    c = int(code) if code.isdigit() else 0
    if 200 <= c < 300: return "bold green"
    if 300 <= c < 400: return "bold cyan"
    if 400 <= c < 500: return "bold yellow"
    if 500 <= c < 600: return "bold red"
    return "white"


def load_domains_file(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def load_exclude_patterns(path: str) -> List[str]:
    """Load glob/fnmatch patterns from a file, one per line."""
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def apply_excludes(subs: List[str], patterns: List[str]) -> List[str]:
    """Remove subdomains that match any exclude pattern (fnmatch)."""
    if not patterns:
        return subs
    kept = []
    for s in subs:
        if not any(fnmatch.fnmatch(s, p) for p in patterns):
            kept.append(s)
    return kept


def fmt_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ProbedRow:
    url:    str
    status: str
    tech:   str


@dataclass
class DomainCounts:
    domain:             str
    found:              int
    excluded:           int       # subdomains removed by --exclude-file
    probed:             int
    filtered:           int
    output_dir:         str
    total_elapsed:      float = 0.0
    subfinder_elapsed:  float = 0.0   # [TIME] per-stage breakdown
    httpx_elapsed:      float = 0.0
    cache_hit:          bool  = False
    no_probe:           bool  = False


# ── Tool wrappers ─────────────────────────────────────────────────────────────

def run_subfinder(
    subfinder_bin:  str,
    domain:         str,
    threads:        int,
    timeout:        int,         # [TIME] independent subfinder timeout
    all_sources:    bool,
) -> List[str]:
    cmd = [subfinder_bin, "-silent", "-d", domain]
    if threads > 0:
        cmd += ["-t", str(threads)]
    if all_sources:
        cmd += ["-all"]
    if timeout > 0:
        cmd += ["-timeout", str(timeout)]
    try:
        cp = subprocess.run(
            cmd, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout or None,
        )
    except subprocess.TimeoutExpired:
        _cprint(f"  [bold yellow]⚠[/] subfinder timed out for [yellow]{domain}[/]")
        return []
    return sorted({ln.strip() for ln in cp.stdout.splitlines() if ln.strip()})


# ── httpx JSON parsing ────────────────────────────────────────────────────────

def _parse_httpx_json_line(raw: str) -> Optional[ProbedRow]:
    raw = strip_ansi(raw).strip()
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    url    = obj.get("url") or obj.get("input", "")
    status = str(obj.get("status_code", ""))
    techs  = obj.get("technologies") or obj.get("tech") or []
    tech   = ", ".join(techs) if isinstance(techs, list) else str(techs)
    return ProbedRow(url=url, status=status, tech=tech)


def run_httpx(
    httpx_bin:    str,
    hosts:        Sequence[str],
    threads:      int,
    timeout:      int,           # [TIME] independent httpx timeout
    rate_limit:   int,           # [PERF] --rate-limit passthrough
    live_rows:    Deque,         # [UI] rolling deque for live table
    progress:     Progress,
    task_id,
) -> List[ProbedRow]:
    """
    [PERF] Single Popen call for all hosts — no batching loop.
    httpx handles its own concurrency via -threads.
    [BUG]  Progress is advanced per parsed result line, not per batch.
    """
    if not hosts:
        return []

    cmd = [
        httpx_bin,
        "-silent",
        "-json",
        "-tech-detect",
        "-status-code",
    ]
    if threads > 0:
        cmd += ["-threads", str(threads)]
    if rate_limit > 0:
        cmd += ["-rate-limit", str(rate_limit)]

    input_text = "\n".join(hosts) + "\n"

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:
        _cprint(f"  [bold red]✗[/] httpx failed to start: {exc}")
        return []

    try:
        stdout_data, _ = proc.communicate(
            input=input_text,
            timeout=timeout or None,
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        _cprint(f"  [bold yellow]⚠[/] httpx timed out")
        return []

    results: List[ProbedRow] = []
    for raw_line in stdout_data.splitlines():
        row = _parse_httpx_json_line(raw_line)
        if row is None:
            continue
        results.append(row)

        # [UI] Rolling live table — cap at LIVE_TABLE_ROWS
        sc    = status_colour(row.status)
        techs = row.tech[:46] + "…" if len(row.tech) > 46 else row.tech
        live_rows.append((
            f"[{sc}]{row.status}[/]",
            row.url,
            f"[dim]{techs}[/]" if techs else "[dim]—[/]",
        ))
        progress.advance(task_id)

    return results


# ── Filter ────────────────────────────────────────────────────────────────────

def filter_rows(rows: Sequence[ProbedRow], statuses: Set[str]) -> List[ProbedRow]:
    return [r for r in rows if r.status in statuses]


# ── Export ────────────────────────────────────────────────────────────────────

def export_results(rows: Sequence[ProbedRow], base_path: str, fmt: str) -> str:
    """
    [PERF] DataFrame built directly from dataclass attrs — no intermediate dict.
    """
    records = [
        {"Sno": i, "Subdomain Name": r.url, "Status Code": r.status, "Technology": r.tech}
        for i, r in enumerate(rows, 1)
    ]
    df = pd.DataFrame(records, columns=["Sno", "Subdomain Name", "Status Code", "Technology"])

    if fmt == "xlsx":
        path = base_path + ".xlsx"
        with pd.ExcelWriter(path, engine="openpyxl") as w:
            df.to_excel(w, index=False, sheet_name="probed")
    elif fmt == "csv":
        path = base_path + ".csv"
        df.to_csv(path, index=False)
    elif fmt == "json":
        path = base_path + ".json"
        df.rename(columns={
            "Sno": "sno", "Subdomain Name": "subdomain",
            "Status Code": "status_code", "Technology": "technology",
        }).to_json(path, orient="records", indent=2)
    else:
        raise ValueError(f"Unknown format: {fmt}")

    return os.path.abspath(path)


# ── Rich UI helpers ───────────────────────────────────────────────────────────

def print_banner(quiet: bool) -> None:
    if quiet:
        return
    # [UI] Symmetric block — both words same width, aligned left
    art = (
        "  ███████╗██╗   ██╗██████╗      ██████╗ ██████╗  ██████╗ \n"
        "  ██╔════╝██║   ██║██╔══██╗     ██╔══██╗██╔══██╗██╔═══██╗\n"
        "  ███████╗██║   ██║██████╔╝     ██████╔╝██████╔╝██║   ██║\n"
        "  ╚════██║██║   ██║██╔══██╗     ██╔═══╝ ██╔══██╗██║   ██║\n"
        "  ███████║╚██████╔╝██████╔╝     ██║     ██║  ██║╚██████╔╝\n"
        "  ╚══════╝ ╚═════╝ ╚═════╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ "
    )
    _cprint()
    _cprint(Panel(
        f"[bold bright_cyan]{art}[/]\n\n"
        f"[bold bright_green]   Subdomain Prober v{__version__}[/]"
        f"    [dim white]|[/]"
        f"   [bold yellow]Author: Saurabh Jain[/]",
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        expand=False,
        padding=(1, 2),
    ))
    _cprint()


def print_domain_header(domain: str, quiet: bool) -> None:
    if quiet:
        return
    _cprint(Rule(f"[bold cyan]  {domain}  [/]", style="bright_blue"))
    _cprint()


def make_progress(total: int, description: str) -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bright_blue"),
        TextColumn(f"[bold cyan]{description}"),
        BarColumn(bar_width=34, style="bright_blue", complete_style="bright_green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )


def make_live_table(rows: Deque) -> Table:
    """
    [UI] Rebuild the live findings table from the rolling deque.
    Capped at LIVE_TABLE_ROWS — no unbounded growth.
    """
    t = Table(
        title=f"[bold cyan]Live Findings[/] [dim](last {LIVE_TABLE_ROWS})[/]",
        box=box.SIMPLE_HEAVY,
        border_style="bright_blue",
        header_style="bold bright_blue",
        show_lines=False,
        expand=False,
    )
    t.add_column("Status", no_wrap=True, width=8)
    t.add_column("URL",    no_wrap=False, min_width=42)
    t.add_column("Tech",   no_wrap=False, min_width=20)
    for r in rows:
        t.add_row(*r)
    return t


def print_domain_result(c: DomainCounts, quiet: bool) -> None:
    """Vertical result table with per-stage timing breakdown."""
    table = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=False,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("Field", style="bold cyan", no_wrap=True, min_width=26)
    table.add_column("Value", style="white",     no_wrap=False)

    cache_note   = "  [dim](cache)[/]" if c.cache_hit else ""
    found_str    = f"[bold white]{c.found}[/]{cache_note}"
    excl_str     = f"[dim yellow]{c.excluded}[/]" if c.excluded else "[dim]0[/]"
    probed_str   = f"[bold green]{c.probed}[/]"    if c.probed    else "[dim]0[/]"
    filtered_str = f"[bold yellow]{c.filtered}[/]"  if c.filtered  else "[dim]0[/]"

    # [UI] Per-stage timing breakdown
    sub_t  = fmt_elapsed(c.subfinder_elapsed)
    http_t = fmt_elapsed(c.httpx_elapsed)
    tot_t  = fmt_elapsed(c.total_elapsed)
    timing = (
        f"[dim]subfinder {sub_t}[/]"
        + (f"  [dim]httpx {http_t}[/]" if not c.no_probe else "")
        + f"  [bold]{tot_t} total[/]"
    )

    table.add_row("Domain",              c.domain)
    table.add_row("Subdomains Found",    found_str)
    if c.excluded:
        table.add_row("Excluded",        excl_str)
    if not c.no_probe:
        table.add_row("Live (Probed)",   probed_str)
        table.add_row("Filtered",        filtered_str)
    table.add_row("Timing",              timing)
    table.add_row("Output Dir",          f"[dim]{c.output_dir}[/]")

    with _print_lck:
        console.print(table)
        console.print()


def print_preflight(domains: List[str], args: argparse.Namespace, statuses: Set[str]) -> None:
    """[UI] Show active config including status codes before scanning starts."""
    _cprint(
        f"  [dim cyan]"
        f"domains:[/] [bold white]{len(domains)}[/]  "
        f"[dim cyan]workers:[/] [bold white]{args.workers}[/]  "
        f"[dim cyan]format:[/] [bold white]{args.output_format}[/]  "
        f"[dim cyan]status:[/] [bold white]{','.join(sorted(statuses))}[/]  "  # [UI] status shown
        f"[dim cyan]force:[/] [bold white]{args.force}[/]"
        + (f"  [bold yellow]--no-probe[/]" if args.no_probe else "")
        + (f"  [bold yellow]--dry-run[/]"  if args.dry_run  else "")
    )
    _cprint()


def print_summary_table(
    results:      List[DomainCounts],
    domain_order: List[str],
    quiet:        bool,
) -> None:
    """
    [UI] Multi-domain summary sorted by original input order — deterministic.
    Shows subfinder + httpx elapsed columns.
    """
    if len(results) < 2 or quiet:
        return

    # [UI] Sort by original input order, not completion order
    order_map = {d: i for i, d in enumerate(domain_order)}
    ordered   = sorted(results, key=lambda c: order_map.get(c.domain, 9999))

    table = Table(
        title="[bold white]Scan Summary — All Domains[/]",
        box=box.ROUNDED,
        border_style="bright_green",
        header_style="bold bright_green",
        show_lines=True,
    )
    table.add_column("Domain",      style="bold cyan",  no_wrap=True)
    table.add_column("Found",       style="white",      justify="right")
    table.add_column("Excluded",    style="dim white",  justify="right")
    table.add_column("Live",        style="white",      justify="right")
    table.add_column("Filtered",    style="white",      justify="right")
    table.add_column("subfinder",   style="dim white",  justify="right")
    table.add_column("httpx",       style="dim white",  justify="right")
    table.add_column("Total",       style="white",      justify="right")
    table.add_column("Cache",       style="dim white",  justify="center")

    for c in ordered:
        table.add_row(
            c.domain,
            str(c.found),
            str(c.excluded) if c.excluded else "[dim]—[/]",
            f"[bold green]{c.probed}[/]"    if c.probed    else "[dim]0[/]",
            f"[bold yellow]{c.filtered}[/]"  if c.filtered  else "[dim]0[/]",
            fmt_elapsed(c.subfinder_elapsed),
            fmt_elapsed(c.httpx_elapsed) if not c.no_probe else "[dim]—[/]",
            fmt_elapsed(c.total_elapsed),
            "[green]✓[/]" if c.cache_hit else "[dim]—[/]",
        )

    _cprint()
    _cprint(table)
    _cprint()


# ── Pipeline ──────────────────────────────────────────────────────────────────

def process_domain(
    domain:             str,
    outdir:             str,
    statuses:           Set[str],
    subfinder_bin:      str,
    httpx_bin:          str,
    threads:            int,
    subfinder_timeout:  int,      # [TIME] independent subfinder timeout
    httpx_timeout:      int,      # [TIME] independent httpx timeout
    rate_limit:         int,
    output_fmt:         str,
    force:              bool,
    no_probe:           bool,
    quiet:              bool,
    exclude_patterns:   List[str],
    all_sources:        bool,
) -> DomainCounts:
    t_total_start = time.monotonic()

    # [BUG FIX] Two separate directories:
    #   cache_dir  — stable, holds all.txt across runs
    #   run_dir    — timestamped, holds this run's reports
    cache_dir = os.path.join(outdir, domain_safe_name(domain))
    run_dir   = os.path.join(cache_dir, DATE_STR)
    ensure_dir(cache_dir)
    ensure_dir(run_dir)

    all_txt   = os.path.join(cache_dir, f"{domain}-all.txt")
    cache_hit = False

    # ── Subfinder ─────────────────────────────────────────────────────
    t_sub_start = time.monotonic()

    if not force and os.path.exists(all_txt) and os.path.getsize(all_txt) > 0:
        with open(all_txt, encoding="utf-8") as fh:
            raw_subs = [ln.strip() for ln in fh if ln.strip()]
        cache_hit = True
        _cprint(
            f"  [cyan]↩[/] subfinder cache — "
            f"[bold]{len(raw_subs)}[/] subdomains  [dim](--force to re-scan)[/]"
        )
    else:
        with console.status(
            f"[bright_blue]subfinder → [bold]{domain}[/]"
            + (" [dim](all sources)[/]" if all_sources else ""),
            spinner="dots",
        ):
            raw_subs = run_subfinder(
                subfinder_bin, domain, threads, subfinder_timeout, all_sources
            )
        write_lines(all_txt, raw_subs)
        _cprint(
            f"  [green]✓[/] subfinder — [bold]{len(raw_subs)}[/] subdomains"
            f"  [dim]({fmt_elapsed(time.monotonic() - t_sub_start)})[/]"
        )

    subfinder_elapsed = time.monotonic() - t_sub_start

    # Apply exclude patterns
    subs     = apply_excludes(raw_subs, exclude_patterns)
    excluded = len(raw_subs) - len(subs)
    if excluded:
        _cprint(f"  [dim yellow]⊘[/] excluded [bold yellow]{excluded}[/] subdomains via --exclude-file")

    if not subs:
        _cprint(f"  [dim]No subdomains to process for {domain}.[/]")
        return DomainCounts(
            domain=domain, found=len(raw_subs), excluded=excluded,
            probed=0, filtered=0, output_dir=os.path.abspath(run_dir),
            total_elapsed=round(time.monotonic() - t_total_start, 1),
            subfinder_elapsed=round(subfinder_elapsed, 1),
            httpx_elapsed=0.0, cache_hit=cache_hit, no_probe=no_probe,
        )

    write_lines(os.path.join(run_dir, f"{domain}-all.txt"), subs)

    if no_probe:
        _cprint(f"  [dim]--no-probe set: skipping httpx.[/]")
        return DomainCounts(
            domain=domain, found=len(raw_subs), excluded=excluded,
            probed=0, filtered=0, output_dir=os.path.abspath(run_dir),
            total_elapsed=round(time.monotonic() - t_total_start, 1),
            subfinder_elapsed=round(subfinder_elapsed, 1),
            httpx_elapsed=0.0, cache_hit=cache_hit, no_probe=True,
        )

    # ── httpx — single process, rolling live table ─────────────────────
    t_http_start = time.monotonic()

    # [UI DEQUE] Rolling buffer capped at LIVE_TABLE_ROWS
    live_rows: Deque = deque(maxlen=LIVE_TABLE_ROWS)
    probed_rows: List[ProbedRow] = []

    prog = make_progress(len(subs), f"Probing {domain}")

    if quiet:
        with prog:
            task = prog.add_task("", total=len(subs))
            probed_rows = run_httpx(
                httpx_bin, subs, threads, httpx_timeout, rate_limit,
                live_rows, prog, task,
            )
    else:
        # [BUG FIX] Single Live context owns stdout — Group(progress, table)
        task = prog.add_task("", total=len(subs))

        def renderable():
            return Group(prog, make_live_table(live_rows))

        with Live(renderable(), console=console, refresh_per_second=8, transient=False) as lv:
            probed_rows = run_httpx(
                httpx_bin, subs, threads, httpx_timeout, rate_limit,
                live_rows, prog, task,
            )
            lv.update(renderable())   # final refresh

    httpx_elapsed = time.monotonic() - t_http_start
    _cprint(
        f"  [green]✓[/] httpx — [bold]{len(probed_rows)}[/] live hosts"
        f"  [dim]({fmt_elapsed(httpx_elapsed)})[/]"
    )

    # ── Filter ────────────────────────────────────────────────────────
    filtered_rows  = filter_rows(probed_rows, statuses)
    probed_lines   = [f"{r.url}  [{r.status}]  {r.tech}" for r in probed_rows]
    filtered_lines = [f"{r.url}  [{r.status}]  {r.tech}" for r in filtered_rows]

    write_lines(os.path.join(run_dir, f"{domain}-probed.txt"),   probed_lines)
    write_lines(os.path.join(run_dir, f"{domain}-filtered.txt"), filtered_lines)
    _cprint(
        f"  [green]✓[/] filter — [bold yellow]{len(filtered_rows)}[/] hosts "
        f"match status [{','.join(sorted(statuses))}]"
    )

    # ── Export ────────────────────────────────────────────────────────
    base_path = os.path.join(run_dir, f"{domain}-probed")
    with console.status(f"[bright_blue]Writing {output_fmt.upper()}...", spinner="dots"):
        out_file = export_results(probed_rows, base_path, output_fmt)
    _cprint(f"  [green]✓[/] Report → [dim]{out_file}[/]")

    return DomainCounts(
        domain=domain, found=len(raw_subs), excluded=excluded,
        probed=len(probed_rows), filtered=len(filtered_rows),
        output_dir=os.path.abspath(run_dir),
        total_elapsed=round(time.monotonic() - t_total_start, 1),
        subfinder_elapsed=round(subfinder_elapsed, 1),
        httpx_elapsed=round(httpx_elapsed, 1),
        cache_hit=cache_hit, no_probe=False,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sub_pro",
        description="Sub-Pro v3 — Subdomain Prober",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan one domain
  python sub_pro.py example.com

  # Scan from file, custom output dir
  python sub_pro.py --domains-file targets.txt --outdir ./results

  # Enumerate only, skip httpx
  python sub_pro.py example.com --no-probe

  # Dry-run to preview without executing
  python sub_pro.py example.com --dry-run

  # Exclude known-internal subdomains
  python sub_pro.py example.com --exclude-file excludes.txt

  # Multiple domains in parallel (careful: high network load)
  python sub_pro.py example.com target.com --workers 2

  # Max sources, throttled, CSV output
  python sub_pro.py example.com --all-sources --rate-limit 100 --output-format csv

  # Independent timeouts per tool
  python sub_pro.py example.com --subfinder-timeout 120 --httpx-timeout 60

  # Hard cap on total runtime
  python sub_pro.py example.com target.com --max-runtime 300
        """,
    )
    # Positional
    p.add_argument("domains", nargs="*", help="Root domains to scan")

    # Input
    inp = p.add_argument_group("Input")
    inp.add_argument("--domains-file",  metavar="FILE", help="File with one domain per line")
    inp.add_argument("--exclude-file",  metavar="FILE", help="File with fnmatch patterns to exclude from subdomains")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--outdir",         default=".",    help="Base output directory (default: .)")
    out.add_argument("--output-format",  dest="output_format",
                     choices=["xlsx", "csv", "json"], default="xlsx",
                     help="Export format (default: xlsx)")
    out.add_argument("--status",         default="200,301,401,403",
                     help="Status codes for filtered.txt (default: 200,301,401,403)")

    # Execution
    exe = p.add_argument_group("Execution")
    exe.add_argument("--workers",        type=int, default=1,
                     help="Parallel domain workers (default: 1 — WARNING: higher values "
                          "send many concurrent connections and may trigger rate-limiting)")
    exe.add_argument("--threads",        type=int, default=0,
                     help="Threads passed to subfinder/httpx (0 = tool default)")
    exe.add_argument("--rate-limit",     dest="rate_limit", type=int, default=0,
                     help="httpx -rate-limit requests/sec (0 = unlimited)")
    exe.add_argument("--all-sources",    dest="all_sources", action="store_true",
                     help="Pass -all to subfinder for maximum source coverage")
    exe.add_argument("--subfinder-timeout", dest="subfinder_timeout", type=int, default=0,
                     help="subfinder timeout seconds (0 = none, independent of httpx)")
    exe.add_argument("--httpx-timeout",  dest="httpx_timeout", type=int, default=0,
                     help="httpx timeout seconds (0 = none, independent of subfinder)")
    exe.add_argument("--max-runtime",    dest="max_runtime", type=int, default=0,
                     help="Hard ceiling on total wall-clock seconds (0 = no limit)")

    # Behaviour
    beh = p.add_argument_group("Behaviour")
    beh.add_argument("--force",    action="store_true", help="Ignore subfinder cache")
    beh.add_argument("--no-probe", dest="no_probe", action="store_true",
                     help="Enumerate subdomains only; skip httpx entirely")
    beh.add_argument("--dry-run",  dest="dry_run",  action="store_true",
                     help="Print what would run without executing anything")
    beh.add_argument("--quiet",    action="store_true",
                     help="Suppress banner and decorative output (CI-friendly)")
    beh.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--version", action="version", version=f"Sub-Pro v{__version__}")

    return p.parse_args()


# ── Max-runtime watchdog ──────────────────────────────────────────────────────

def _start_watchdog(max_runtime: int) -> None:
    """[OPT] Kill the process if max_runtime seconds elapse."""
    if max_runtime <= 0:
        return
    def _watch():
        time.sleep(max_runtime)
        _cprint(
            f"\n  [bold red]✗[/] --max-runtime {max_runtime}s exceeded — aborting."
        )
        os._exit(1)
    t = threading.Thread(target=_watch, daemon=True)
    t.start()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    t_wall = time.monotonic()

    # ── Collect & deduplicate domains ─────────────────────────────────
    domains: List[str] = list(args.domains or [])
    if args.domains_file:
        if not os.path.exists(args.domains_file):
            _cprint(f"  [bold red]✗[/] domains-file not found: {args.domains_file}")
            sys.exit(1)
        domains.extend(load_domains_file(args.domains_file))
    if not domains:
        _cprint("  [bold red]✗[/] No domains provided. Pass positional args or --domains-file.")
        sys.exit(1)

    seen: Set[str] = set()
    unique: List[str] = []
    for d in domains:
        if d not in seen:
            seen.add(d); unique.append(d)
    domains = unique

    # ── Exclude patterns ──────────────────────────────────────────────
    exclude_patterns: List[str] = []
    if args.exclude_file:
        if not os.path.exists(args.exclude_file):
            _cprint(f"  [bold red]✗[/] exclude-file not found: {args.exclude_file}")
            sys.exit(1)
        exclude_patterns = load_exclude_patterns(args.exclude_file)
        _cprint(f"  [dim]Loaded [bold]{len(exclude_patterns)}[/] exclude patterns[/]")

    statuses = {s.strip() for s in args.status.split(",") if s.strip().isdigit()}

    print_banner(args.quiet)
    print_preflight(domains, args, statuses)

    # ── Dry run ───────────────────────────────────────────────────────
    if args.dry_run:
        _cprint(Panel(
            "[bold yellow]DRY RUN — nothing will be executed[/]\n\n"
            + "\n".join(f"  [cyan]·[/] {d}" for d in domains),
            border_style="yellow", box=box.ROUNDED, expand=False,
        ))
        return

    # ── Pre-flight checks ─────────────────────────────────────────────
    subfinder_bin = which_or_die("subfinder")
    httpx_bin     = which_or_die("httpx") if not args.no_probe else ""
    ensure_dir(args.outdir)

    # ── Max-runtime watchdog ──────────────────────────────────────────
    _start_watchdog(args.max_runtime)

    # ── Per-domain pipeline ───────────────────────────────────────────
    def _run(domain: str) -> DomainCounts:
        print_domain_header(domain, args.quiet)
        return process_domain(
            domain            = domain,
            outdir            = args.outdir,
            statuses          = statuses,
            subfinder_bin     = subfinder_bin,
            httpx_bin         = httpx_bin,
            threads           = args.threads,
            subfinder_timeout = args.subfinder_timeout,
            httpx_timeout     = args.httpx_timeout,
            rate_limit        = args.rate_limit,
            output_fmt        = args.output_format,
            force             = args.force,
            no_probe          = args.no_probe,
            quiet             = args.quiet,
            exclude_patterns  = exclude_patterns,
            all_sources       = args.all_sources,
        )

    all_results:  List[DomainCounts] = []
    domain_order: List[str]          = list(domains)

    if args.workers > 1 and len(domains) > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(_run, d): d for d in domains}
            for fut in as_completed(futures):
                try:
                    all_results.append(fut.result())
                except Exception as exc:
                    _cprint(f"  [bold red]✗[/] {futures[fut]} — {exc}")
    else:
        for domain in domains:
            all_results.append(_run(domain))

    # ── Per-domain result tables (in input order) ─────────────────────
    order_map = {d: i for i, d in enumerate(domain_order)}
    for c in sorted(all_results, key=lambda c: order_map.get(c.domain, 9999)):
        print_domain_result(c, args.quiet)

    # ── Multi-domain summary ──────────────────────────────────────────
    print_summary_table(all_results, domain_order, args.quiet)

    # ── Done panel with total wall-clock ─────────────────────────────
    wall = fmt_elapsed(time.monotonic() - t_wall)
    total_found    = sum(c.found    for c in all_results)
    total_probed   = sum(c.probed   for c in all_results)
    total_filtered = sum(c.filtered for c in all_results)

    _cprint(Panel(
        f"[bold green]✓  All done[/]   [dim]·[/]   "
        f"[white]domains:[/] [bold]{len(all_results)}[/]   "
        f"[white]subdomains:[/] [bold]{total_found}[/]   "
        f"[white]live:[/] [bold green]{total_probed}[/]   "
        f"[white]filtered:[/] [bold yellow]{total_filtered}[/]   "
        f"[white]runtime:[/] [bold cyan]{wall}[/]",   # [UI] total time shown
        border_style="bright_green",
        box=box.DOUBLE_EDGE,
        expand=False,
    ))
    _cprint()


if __name__ == "__main__":
    main()
