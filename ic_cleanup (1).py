#!/usr/bin/env python3
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    python ic_cleanup.py <scan_root> [options]

Options:
    --output FILE        Write results to a file in addition to stdout
    --delete             Actually delete files (default: dry-run, list only)
    --level LEVEL [...]  Show only specific risk level(s):
                           low | medium | high | dont_touch | keep_current

Rule format (RULES list):
    Each rule is a dict with the following keys:

    Required:
        pattern  (str)  : regex matched against the entry basename
        type     (str)  : "f" = file only, "d" = directory only, "fd" = both
        level    (str)  : LOW / MEDIUM / HIGH / DONT / KEEP_CURRENT

    Optional:
        parent   (str)  : regex matched against the immediate parent dir name
                          omit (or None) to match any parent
        desc     (str)  : human-readable label shown in output

    Rules are evaluated top-to-bottom; first match wins.

keep_current logic:
    When a rule has level=KEEP_CURRENT, the tool resolves every symlink whose
    name contains "current" (case-insensitive) inside the same parent directory.
    The real target directory name is collected and protected -- any sibling that
    matches the rule pattern but is NOT that target is flagged as LOW risk.
"""

import argparse
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ===========================================================================
#  ANSI color helpers  (auto-disabled when stdout is not a tty)
# ===========================================================================
_USE_COLOR = sys.stdout.isatty()

_ANSI = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    # foreground colors
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "blue":   "\033[34m",
    "white":  "\033[37m",
    # dim / dark
    "dim":    "\033[2m",
}


def _c(text: str, *codes: str) -> str:
    """Wrap text with ANSI codes if color is enabled."""
    if not _USE_COLOR:
        return text
    prefix = "".join(_ANSI.get(c, "") for c in codes)
    return "{}{}{}".format(prefix, text, _ANSI["reset"])


# ===========================================================================
#  Risk level constants
# ===========================================================================
LOW          = "Low Risk"
MEDIUM       = "Medium Risk"
HIGH         = "High Risk"
DONT         = "DON'T TOUCH"
KEEP_CURRENT = "Keep-Current"

ALL_LEVELS = (LOW, MEDIUM, HIGH, DONT, KEEP_CURRENT)

# Plain tags (used in file output, no color)
_LEVEL_TAG_PLAIN = {
    LOW:          "[LOW    ]",
    MEDIUM:       "[MEDIUM ]",
    HIGH:         "[HIGH   ]",
    DONT:         "[DONT   ]",
    KEEP_CURRENT: "[KEEP   ]",
}

# Colored tags (used on terminal)
_LEVEL_TAG_COLOR = {
    LOW:          _c("[LOW    ]", "green",  "bold"),
    MEDIUM:       _c("[MEDIUM ]", "yellow", "bold"),
    HIGH:         _c("[HIGH   ]", "red",    "bold"),
    DONT:         _c("[DONT   ]", "cyan",   "bold"),
    KEEP_CURRENT: _c("[KEEP   ]", "blue",   "bold"),
}


def level_tag(level: str, for_file: bool = False) -> str:
    """Return colored tag for terminal or plain tag for file."""
    if for_file:
        return _LEVEL_TAG_PLAIN[level]
    return _LEVEL_TAG_COLOR[level]


LEVEL_MAP = {
    "low":          LOW,
    "medium":       MEDIUM,
    "high":         HIGH,
    "dont_touch":   DONT,
    "keep_current": KEEP_CURRENT,
}

# ===========================================================================
#  Rule table  --  EDIT HERE TO ADD / REMOVE / REPRIORITIZE RULES
#
#  Keys per rule:
#    pattern  (str, required) : Python regex matched against entry basename
#    type     (str, required) : "f" | "d" | "fd"
#    level    (str, required) : one of the constants above
#    parent   (str, optional) : Python regex matched against parent dir name
#    desc     (str, optional) : label shown in report
#
#  For keep_current rules:
#    - type must be "d"
#    - Any sibling directory matching `pattern` whose name equals the target
#      of a "current*" symlink (case-insensitive) in the same parent will be
#      shown as KEEP_CURRENT (protected).  All other matching siblings are
#      treated as LOW risk (eligible for deletion).
# ===========================================================================
RULES: List[Dict] = [

    # --- Low Risk: simulation waveforms ---
    {"pattern": r".*\.fsdb$",               "type": "f",  "level": LOW,    "desc": "sim waveform"},
    {"pattern": r".*\.vcd$",                "type": "f",  "level": LOW,    "desc": "sim waveform"},
    {"pattern": r".*\.shm$",                "type": "f",  "level": LOW,    "desc": "sim waveform"},
    {"pattern": r".*\.vpd$",                "type": "f",  "level": LOW,    "desc": "sim waveform"},

    # --- Low Risk: compile / run cache ---
    {"pattern": r".*INCA_libs$",            "type": "d",  "level": LOW,    "desc": "compile cache dir"},
    {"pattern": r".*xcelium\.d$",           "type": "d",  "level": LOW,    "desc": "compile cache dir"},
    {"pattern": r"^csrc$",                  "type": "d",  "level": LOW,    "desc": "compile cache dir"},
    {"pattern": r"^simv$",                  "type": "f",  "level": LOW,    "desc": "sim binary"},
    {"pattern": r"^simv\.daidir$",          "type": "d",  "level": LOW,    "desc": "sim binary dir"},

    # --- Low Risk: log files ---
    {"pattern": r".*\.log$",                "type": "f",  "level": LOW,    "desc": "log file"},
    {"pattern": r".*sim\.log$",             "type": "f",  "level": LOW,    "desc": "sim log"},

    # --- Low Risk: editor swap ---
    {"pattern": r".*\.swp$",                "type": "f",  "level": LOW,    "desc": "vim swap file"},

    # --- Low Risk: crte temp files ---
    {"pattern": r"^crte_.*\.txt$",          "type": "f",  "level": LOW,    "desc": "crte temp file"},

    # --- Low Risk: work_restore directory ---
    {"pattern": r"^work_restore$",          "type": "d",  "level": LOW,    "desc": "work restore dir"},

    # --- Low Risk: STA workspace ---
    {"pattern": r"^DMSA_output_",           "type": "d",  "level": LOW,    "desc": "STA workspace"},
    {"pattern": r"^PT_output_",             "type": "d",  "level": LOW,    "desc": "STA workspace"},
    {"pattern": r".*PT_session$",           "type": "d",  "level": LOW,    "desc": "PT session dir"},
    {"pattern": r".*PC_session$",           "type": "d",  "level": LOW,    "desc": "PC session dir"},
    {"pattern": r".*TWK_session$",          "type": "d",  "level": LOW,    "desc": "TWK session dir"},
    {"pattern": r"^save_bf_session$",       "type": "d",  "level": LOW,    "desc": "STA patch record"},
    {"pattern": r"^save_af_session$",       "type": "d",  "level": LOW,    "desc": "STA patch record"},

    # --- Low Risk: misc tool temp ---
    {"pattern": r".*\.power\.list$",        "type": "f",  "level": LOW,    "desc": "PTPX temp"},
    {"pattern": r".*\.timing$",             "type": "f",  "level": LOW,    "desc": "PTPX temp"},
    {"pattern": r".*checkpoint$",           "type": "fd", "level": LOW,    "desc": "LEC checkpoint"},
    {"pattern": r".*FM_WORK$",              "type": "d",  "level": LOW,    "desc": "Formality work dir"},
    {"pattern": r".*FM_INFO$",              "type": "d",  "level": LOW,    "desc": "Formality info dir"},
    {"pattern": r".*\.fss$",                "type": "f",  "level": LOW,    "desc": "Formality aux"},
    {"pattern": r".*\.svf$",                "type": "f",  "level": LOW,    "desc": "Formality aux"},
    {"pattern": r"^core\.",                 "type": "f",  "level": LOW,    "desc": "system crash dump"},

    # --- Low Risk: special cases ---
    {"pattern": r"^violation_report\.rpt$", "type": "f",  "level": LOW,    "desc": "sg_sdc violation report"},
    {"pattern": r"^vcst_",                  "type": "fd", "level": LOW,    "desc": "VCSG_lint temp"},
    {"pattern": r"^vcst_rtdb$",             "type": "d",  "level": LOW,    "desc": "VCSG_lint rtdb"},
    {"pattern": r"^vcst_rtdb\.bak$",        "type": "d",  "level": LOW,    "desc": "VCSG_lint rtdb backup"},
    {"pattern": r"^idbs$",                  "type": "d",  "level": LOW,    "desc": "nvtClkExp temp"},
    {"pattern": r"^vsi\.tar\.lz4$",         "type": "f",  "level": LOW,    "desc": "nvtCHK temp"},

    # --- Medium Risk ---
    {"pattern": r".*\.ddc$",                "type": "f",  "level": MEDIUM, "desc": "synthesis snapshot"},
    {"pattern": r".*\.saif$",               "type": "f",  "level": MEDIUM, "desc": "power activity file"},
    {"pattern": r".*\.bit$",                "type": "f",  "level": MEDIUM, "desc": "FPGA bitstream"},
    {"pattern": r".*\.bin$",                "type": "f",  "level": MEDIUM, "desc": "FPGA bitstream"},
    {"pattern": r".*\.mcs$",                "type": "f",  "level": MEDIUM, "desc": "FPGA bitstream"},
    {"pattern": r".*\.pat$",                "type": "f",  "level": MEDIUM, "desc": "DFT pattern"},
    {"pattern": r"^PC_output",              "type": "d",  "level": MEDIUM, "desc": "P&R intermediate layout"},
    {"pattern": r".*\.spef$",               "type": "f",  "level": MEDIUM, "desc": "P&R parasitics"},
    {"pattern": r"^lint_cpdb$",             "type": "d",  "level": MEDIUM, "desc": "VCSG_lint cpdb"},

    # --- High Risk ---
    {"pattern": r".*\.v$",                  "type": "f",  "level": HIGH,   "desc": "netlist/RTL (manual confirm)"},
    {"pattern": r".*\.vg$",                 "type": "f",  "level": HIGH,   "desc": "gate-level netlist"},
    {"pattern": r"^report_qor\.rpt$",       "type": "f",  "level": HIGH,   "desc": "STA signoff report"},
    {"pattern": r"^summary_.*\.rpt$",       "type": "f",  "level": HIGH,   "desc": "STA signoff summary"},
    {"pattern": r".*_final\.gds$",          "type": "f",  "level": HIGH,   "desc": "P&R final GDS"},
    {"pattern": r"^ptpx_final",             "type": "fd", "level": HIGH,   "desc": "power signoff"},

    # --- keep_current: MACRO subdirs protected by "current" symlink ---
    # Sibling dirs matching \d{6} under a *MACRO* parent:
    #   -> if it is the symlink target : KEEP_CURRENT  (shown, never deleted)
    #   -> otherwise                   : LOW           (eligible for deletion)
    {
        "pattern": r"^\d{6}$",
        "type":    "d",
        "level":   KEEP_CURRENT,
        "parent":  r".*MACRO.*",
        "desc":    "MACRO versioned snapshot",
    },

    # --- DON'T TOUCH ---
    {"pattern": r".*\.sv$",                 "type": "f",  "level": DONT,   "desc": "RTL source"},
    {"pattern": r".*\.sdc$",                "type": "f",  "level": DONT,   "desc": "timing constraints"},
    {"pattern": r"^Makefile$",              "type": "f",  "level": DONT,   "desc": "project config"},
    {"pattern": r".*\.prj$",                "type": "f",  "level": DONT,   "desc": "project config"},
    {"pattern": r".*\.sgdc$",               "type": "f",  "level": DONT,   "desc": "project config"},
    {"pattern": r".*\.tcl$",                "type": "f",  "level": DONT,   "desc": "flow script"},
    {"pattern": r".*\.py$",                 "type": "f",  "level": DONT,   "desc": "flow script"},
    {"pattern": r".*\.pl$",                 "type": "f",  "level": DONT,   "desc": "flow script"},
]

# Pre-compile all regexes once at import time
for _r in RULES:
    _r["_pat_re"]    = re.compile(_r["pattern"])
    _r["_parent_re"] = re.compile(_r["parent"]) if _r.get("parent") else None


# ===========================================================================
#  "current" symlink resolution  (case-insensitive name match)
# ===========================================================================
_current_cache: Dict[str, Set[str]] = {}


def current_targets_in_dir(parent: Path) -> Set[str]:
    """
    Return the set of resolved real directory names pointed to by any symlink
    whose name contains 'current' (case-insensitive) inside `parent`.
    """
    targets: Set[str] = set()
    try:
        for entry in os.scandir(str(parent)):
            if not entry.is_symlink():
                continue
            if "current" not in entry.name.lower():   # <-- case-insensitive
                continue
            try:
                target = Path(os.readlink(entry.path))
                if not target.is_absolute():
                    target = parent / target
                target = target.resolve()
                if target.is_dir():
                    targets.add(target.name)
            except OSError:
                pass
    except PermissionError:
        pass
    return targets


def get_current_targets(parent: Path) -> Set[str]:
    key = str(parent)
    if key not in _current_cache:
        _current_cache[key] = current_targets_in_dir(parent)
    return _current_cache[key]


# ===========================================================================
#  Classification
# ===========================================================================
def classify(
    name: str,
    parent: Path,
    is_dir: bool,
) -> Optional[Tuple[str, str]]:
    """
    Return (effective_level, description) or None.
    For KEEP_CURRENT rules the returned level is:
      KEEP_CURRENT  if this entry is the target of a 'current' symlink
      LOW           otherwise
    """
    entry_type = "d" if is_dir else "f"

    for rule in RULES:
        if entry_type not in rule["type"]:
            continue
        if not rule["_pat_re"].search(name):
            continue
        if rule["_parent_re"] and not rule["_parent_re"].search(parent.name):
            continue

        level = rule["level"]
        desc  = rule.get("desc", "")

        if level == KEEP_CURRENT:
            protected = get_current_targets(parent)
            if name in protected:
                return KEEP_CURRENT, desc
            return LOW, desc

        return level, desc

    return None


# ===========================================================================
#  Formatting helpers
# ===========================================================================
def human_size(nbytes: float) -> str:
    if nbytes == 0:
        return "0.0 B"
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return "{:.1f} {}".format(size, unit)
        size /= 1024.0
    return "{:.1f} PB".format(size)


def fmt_mtime(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def dir_total_size(path: Path) -> int:
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file() and not f.is_symlink():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
    except PermissionError:
        pass
    return total


# Column widths for the plain (no-color) tag  "[MEDIUM ]" = 9 chars
_TAG_WIDTH = len("[MEDIUM ]")

HEADER_PLAIN = "{:>12}  {:<16}  {:<{w}}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "PATH", w=_TAG_WIDTH
)
SEP = "-" * 110


def fmt_row(
    size: int,
    mtime: float,
    level: str,
    rel_path: str,
    for_file: bool = False,
) -> str:
    tag = level_tag(level, for_file=for_file)
    # For terminal the tag contains ANSI escapes; pad using the plain width
    # so columns stay aligned regardless of invisible escape characters.
    if for_file or not _USE_COLOR:
        tag_col = "{:<{w}}".format(tag, w=_TAG_WIDTH)
    else:
        tag_col = tag   # ANSI codes are invisible; alignment is already fixed
    return "{:>12}  {:<16}  {}  {}".format(
        human_size(size),
        fmt_mtime(mtime),
        tag_col,
        rel_path,
    )


# ===========================================================================
#  Progress line (scanning status, overwritten in-place on tty)
# ===========================================================================
_TERM_WIDTH = shutil.get_terminal_size((120, 24)).columns

def _progress(current_dir: str) -> None:
    """Print a transient 'Scanning ...' line that overwrites itself."""
    if not _USE_COLOR:
        return
    label = _c("Scanning: ", "dim") + _c(current_dir, "dim")
    # truncate to terminal width minus a small margin
    max_len = _TERM_WIDTH - 4
    if len(current_dir) + len("Scanning: ") > max_len:
        visible = "Scanning: ..." + current_dir[-(max_len - 13):]
    else:
        visible = "Scanning: " + current_dir
    # \r moves to start of line; padding spaces erase previous longer text
    sys.stderr.write("\r{:<{w}}".format(
        _c(visible, "dim"), w=_TERM_WIDTH
    ))
    sys.stderr.flush()


def _clear_progress() -> None:
    if not _USE_COLOR:
        return
    sys.stderr.write("\r{}\r".format(" " * _TERM_WIDTH))
    sys.stderr.flush()


# ===========================================================================
#  emit: write to stdout + optional file handle
# ===========================================================================
def emit(line_term: str, line_file: str, fh) -> None:
    """
    line_term : version with ANSI color codes  (printed to stdout)
    line_file : plain version                  (written to file)
    """
    # Clear the progress line before printing a result row so they don't mix
    _clear_progress()
    print(line_term)
    if fh:
        fh.write(line_file + "\n")


# ===========================================================================
#  Streaming scan
# ===========================================================================
def scan_and_print(
    root: Path,
    level_filter: Optional[Set[str]],
    output_fh,
) -> List[Tuple[int, float, str, Path]]:

    header_term = _c("{:>12}  {:<16}  {:<{w}}  {}".format(
        "SIZE", "MODIFIED", "LEVEL", "PATH", w=_TAG_WIDTH
    ), "bold")
    emit(header_term, HEADER_PLAIN, output_fh)
    emit(SEP, SEP, output_fh)

    results: List[Tuple[int, float, str, Path]] = []
    counts: Dict[str, int] = {lv: 0 for lv in ALL_LEVELS}

    for dirpath, dirnames, filenames in os.walk(str(root)):
        dp = Path(dirpath)

        # Show current directory being scanned (stderr, transient)
        _progress(dirpath)

        # --- directories ---
        for dname in list(dirnames):
            if dp.is_symlink():
                continue
            full = dp / dname
            if full.is_symlink():
                continue

            result = classify(dname, dp, is_dir=True)
            if result is None:
                continue
            level, _desc = result

            # always prune to avoid descending into matched dirs
            dirnames.remove(dname)

            if level_filter and level not in level_filter:
                continue

            try:
                st   = full.stat()
                size = dir_total_size(full)
                mt   = st.st_mtime
            except PermissionError:
                continue

            rel = str(full.relative_to(root))
            emit(
                fmt_row(size, mt, level, rel, for_file=False),
                fmt_row(size, mt, level, rel, for_file=True),
                output_fh,
            )
            results.append((size, mt, level, full))
            counts[level] += 1

        # --- files ---
        for fname in filenames:
            full = dp / fname
            if full.is_symlink():
                continue

            result = classify(fname, dp, is_dir=False)
            if result is None:
                continue
            level, _desc = result

            if level_filter and level not in level_filter:
                continue

            try:
                st   = full.stat()
                size = st.st_size
                mt   = st.st_mtime
            except PermissionError:
                continue

            rel = str(full.relative_to(root))
            emit(
                fmt_row(size, mt, level, rel, for_file=False),
                fmt_row(size, mt, level, rel, for_file=True),
                output_fh,
            )
            results.append((size, mt, level, full))
            counts[level] += 1

    _clear_progress()

    # --- summary ---
    total_size  = sum(r[0] for r in results)
    total_count = len(results)

    emit(SEP, SEP, output_fh)
    summary = (
        "Total {} items  |  "
        "Low: {}  Medium: {}  High: {}  DON'T TOUCH: {}  Keep-Current: {}  |  "
        "Est. size: {}"
    ).format(
        total_count,
        counts[LOW], counts[MEDIUM], counts[HIGH], counts[DONT], counts[KEEP_CURRENT],
        human_size(total_size),
    )
    emit(_c(summary, "bold"), summary, output_fh)

    return results


# ===========================================================================
#  Delete  (dry-run by default)
# ===========================================================================
def do_delete(results: List[Tuple], dry_run: bool) -> None:
    deletable = [r for r in results if r[2] in (LOW, MEDIUM)]

    if not deletable:
        print("\nNothing to delete. (High / DON'T TOUCH / Keep-Current are never auto-deleted.)")
        return

    tag_label = _c("[DRY-RUN]", "yellow", "bold") if dry_run else _c("[DELETE] ", "red", "bold")
    print("\n{} {} items eligible (Low + Medium only):\n".format(tag_label, len(deletable)))

    for _size, _mt, level, path in deletable:
        print("  {}  {}  {}".format(tag_label, level_tag(level), path))
        if not dry_run:
            try:
                if path.is_dir():
                    shutil.rmtree(str(path))
                else:
                    path.unlink()
            except Exception as exc:
                print("             ERROR: {}".format(exc))

    if dry_run:
        print("\n  (Add --delete to actually remove the files above.)")


# ===========================================================================
#  CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IC Design project file cleanup & risk classification tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("root",
        help="Root directory to scan")
    p.add_argument("--output", metavar="FILE", default=None,
        help="Also write the report to FILE (plain text, no color codes)")
    p.add_argument("--delete", action="store_true", default=False,
        help="Actually delete Low/Medium-risk files (default: dry-run)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output (one or more): low medium high dont_touch keep_current")
    return p


def main() -> None:
    args = build_parser().parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print("ERROR: directory not found: {}".format(root), file=sys.stderr)
        sys.exit(1)

    level_filter: Optional[Set[str]] = None
    if args.level:
        level_filter = {LEVEL_MAP[l] for l in args.level}

    print("Scanning: {}\n".format(_c(str(root), "bold")))

    output_fh = None
    if args.output:
        try:
            output_fh = open(args.output, "w", encoding="utf-8")
            output_fh.write("# IC Cleanup report\n")
            output_fh.write("# Root  : {}\n".format(root))
            output_fh.write("# Date  : {}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_fh.write("# Filter: {}\n\n".format(
                ", ".join(args.level) if args.level else "all"
            ))
        except OSError as exc:
            print("ERROR: cannot open output file: {}".format(exc), file=sys.stderr)
            sys.exit(1)

    try:
        results = scan_and_print(root, level_filter, output_fh)
    finally:
        if output_fh:
            output_fh.close()
            print("\nReport written to: {}".format(
                _c(str(Path(args.output).resolve()), "cyan")
            ))

    if not results:
        print("\nNo matching files found.")
        return

    print()
    do_delete(results, dry_run=not args.delete)


if __name__ == "__main__":
    main()
