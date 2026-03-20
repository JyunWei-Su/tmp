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
        ancestor (str)  : regex matched against ANY ancestor dir name in the
                          path from root down to the entry's parent.
                          Omit (or None) to match regardless of ancestry.
        desc     (str)  : human-readable label shown in output

    Rules are evaluated top-to-bottom; first match wins.
    Once a directory matches a rule it is NOT descended into.

keep_current logic:
    When a rule carries level=KEEP_CURRENT the tool looks at all symlinks
    whose name contains "current" (case-insensitive) that live in the SAME
    directory as the candidate entry.  The resolved target basename is
    collected into a protected set.

    candidate name IN protected  ->  shown as KEEP_CURRENT (never deleted)
    candidate name NOT protected ->  shown as LOW           (eligible for deletion)
"""

import argparse
import os
import re
import shutil
import signal
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
    "dim":    "\033[2m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "blue":   "\033[34m",
}


def _c(text: str, *codes: str) -> str:
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

_LEVEL_TAG_PLAIN = {
    LOW:          "[LOW    ]",
    MEDIUM:       "[MEDIUM ]",
    HIGH:         "[HIGH   ]",
    DONT:         "[DONT   ]",
    KEEP_CURRENT: "[KEEP   ]",
}

_LEVEL_TAG_COLOR = {
    LOW:          _c("[LOW    ]", "green",  "bold"),
    MEDIUM:       _c("[MEDIUM ]", "yellow", "bold"),
    HIGH:         _c("[HIGH   ]", "red",    "bold"),
    DONT:         _c("[DONT   ]", "cyan",   "bold"),
    KEEP_CURRENT: _c("[KEEP   ]", "blue",   "bold"),
}


def level_tag(level: str, for_file: bool = False) -> str:
    return _LEVEL_TAG_PLAIN[level] if for_file else _LEVEL_TAG_COLOR[level]


LEVEL_MAP = {
    "low":          LOW,
    "medium":       MEDIUM,
    "high":         HIGH,
    "dont_touch":   DONT,
    "keep_current": KEEP_CURRENT,
}

# ===========================================================================
#  Rule table
#
#  Keys:
#    pattern  (str, required) : Python regex matched against entry basename
#    type     (str, required) : "f" | "d" | "fd"
#    level    (str, required) : LOW / MEDIUM / HIGH / DONT / KEEP_CURRENT
#    ancestor (str, optional) : Python regex matched against ANY ancestor
#                               directory name between root and the entry.
#                               Omit to match regardless of location.
#    desc     (str, optional) : label shown in report
#
#  Rules are evaluated top-to-bottom; first match wins.
#  Matched directories are pruned (never descended into).
#
#  keep_current:
#    Siblings whose name is the resolved target of any "current*" symlink
#    (case-insensitive) in the same directory are protected (KEEP_CURRENT).
#    All other pattern-matching siblings become LOW.
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

    # --- keep_current: versioned snapshot dirs under any MACRO ancestor ---
    #
    # Structure example:
    #   MACRO/sram/
    #     000111/          <- LOW  (no symlink points here)
    #     000112/          <- KEEP_CURRENT  (current -> 000112)
    #     current -> 000112
    #
    # 'ancestor' matches ANY directory in the path above the entry, so
    # MACRO/sram/000112 and deep/nested/MACRO/ip/sram/000112 both match.
    {
        "pattern":  r"^\d{6}$",
        "type":     "d",
        "level":    KEEP_CURRENT,
        "ancestor": r".*MACRO.*",
        "desc":     "MACRO versioned snapshot",
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
    _r["_pat_re"]      = re.compile(_r["pattern"])
    _r["_ancestor_re"] = re.compile(_r["ancestor"]) if _r.get("ancestor") else None


# ===========================================================================
#  Ancestor path check
# ===========================================================================
def has_ancestor_match(path: Path, root: Path, ancestor_re: re.Pattern) -> bool:
    """
    Return True if any directory component between root (exclusive) and
    path's parent (inclusive) matches ancestor_re.
    """
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return False
    # rel_parts includes the entry name itself as the last element;
    # we only check the directory components above it (all but the last)
    for part in rel_parts[:-1]:
        if ancestor_re.search(part):
            return True
    return False


# ===========================================================================
#  "current" symlink resolution  (case-insensitive, cached per directory)
# ===========================================================================
_current_cache: Dict[str, Set[str]] = {}


def current_targets_in_dir(parent: Path) -> Set[str]:
    """
    Return the set of real directory basenames that any symlink whose name
    contains 'current' (case-insensitive) inside `parent` resolves to.
    Broken symlinks and symlinks pointing to files are ignored.
    """
    targets: Set[str] = set()
    try:
        for entry in os.scandir(str(parent)):
            if not entry.is_symlink():
                continue
            if "current" not in entry.name.lower():
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
    root: Path,
    is_dir: bool,
) -> Optional[Tuple[str, str]]:
    """
    Return (effective_level, description) or None if no rule matches.

    ancestor check: any directory component in the path from root down to
                    parent is tested against rule["ancestor"] regex.

    keep_current:   effective level is KEEP_CURRENT if this entry's name is
                    the resolved target of a 'current*' symlink in parent,
                    otherwise LOW.
    """
    entry_type = "d" if is_dir else "f"
    full_path  = parent / name

    for rule in RULES:
        # type check
        if entry_type not in rule["type"]:
            continue
        # basename regex
        if not rule["_pat_re"].search(name):
            continue
        # ancestor regex (any ancestor dir name must match)
        if rule["_ancestor_re"] is not None:
            if not has_ancestor_match(full_path, root, rule["_ancestor_re"]):
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


_TAG_WIDTH  = len("[MEDIUM ]")
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
    return "{:>12}  {:<16}  {}  {}".format(
        human_size(size),
        fmt_mtime(mtime),
        tag,
        rel_path,
    )


# ===========================================================================
#  Progress line on stderr (transient, overwritten each update)
# ===========================================================================
_TERM_WIDTH = shutil.get_terminal_size((120, 24)).columns


def _progress(current_dir: str) -> None:
    if not _USE_COLOR:
        return
    label    = "Scanning: " + current_dir
    max_len  = _TERM_WIDTH - 2
    if len(label) > max_len:
        label = "Scanning: ..." + current_dir[-(max_len - 13):]
    sys.stderr.write("\r{:<{w}}".format(_c(label, "dim"), w=_TERM_WIDTH))
    sys.stderr.flush()


def _clear_progress() -> None:
    if not _USE_COLOR:
        return
    sys.stderr.write("\r{}\r".format(" " * _TERM_WIDTH))
    sys.stderr.flush()


# ===========================================================================
#  emit: stdout + optional file handle
# ===========================================================================
def emit(line_term: str, line_file: str, fh) -> None:
    _clear_progress()
    print(line_term)
    if fh:
        fh.write(line_file + "\n")


# ===========================================================================
#  Interrupt handling
# ===========================================================================
_interrupted = False


def _handle_sigint(signum, frame):
    global _interrupted
    _interrupted = True
    _clear_progress()
    print(_c("\n[INTERRUPTED] Ctrl-C caught -- stopping scan, printing partial results...", "yellow", "bold"),
          file=sys.stderr)


def _install_sigint_handler():
    signal.signal(signal.SIGINT, _handle_sigint)


# ===========================================================================
#  Streaming scan
# ===========================================================================
def scan_and_print(
    root: Path,
    level_filter: Optional[Set[str]],
    output_fh,
) -> List[Tuple[int, float, str, Path]]:

    header_term = _c(HEADER_PLAIN, "bold")
    emit(header_term, HEADER_PLAIN, output_fh)
    emit(SEP, SEP, output_fh)

    results: List[Tuple[int, float, str, Path]] = []
    counts: Dict[str, int] = {lv: 0 for lv in ALL_LEVELS}

    for dirpath, dirnames, filenames in os.walk(str(root)):
        if _interrupted:
            dirnames.clear()   # stop os.walk from descending further
            break

        dp = Path(dirpath)
        _progress(dirpath)

        # --- directories ---
        for dname in list(dirnames):
            if _interrupted:
                break
            if dp.is_symlink():
                continue
            full = dp / dname
            if full.is_symlink():
                continue

            result = classify(dname, dp, root, is_dir=True)
            if result is None:
                continue
            level, _desc = result

            # prune regardless of filter -- never descend into matched dirs
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
            if _interrupted:
                break
            full = dp / fname
            if full.is_symlink():
                continue

            result = classify(fname, dp, root, is_dir=False)
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
    partial_note = "  [PARTIAL - scan interrupted]" if _interrupted else ""
    summary = (
        "Total {} items  |  "
        "Low: {}  Medium: {}  High: {}  DON'T TOUCH: {}  Keep-Current: {}  |  "
        "Est. size: {}{}"
    ).format(
        total_count,
        counts[LOW], counts[MEDIUM], counts[HIGH], counts[DONT], counts[KEEP_CURRENT],
        human_size(total_size),
        partial_note,
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
        if _interrupted:
            print(_c("  [INTERRUPTED] delete aborted.", "yellow"))
            break
        print("  {}  {}  {}".format(tag_label, level_tag(level), path))
        if not dry_run:
            try:
                if path.is_dir():
                    shutil.rmtree(str(path))
                else:
                    path.unlink()
            except Exception as exc:
                print("             ERROR: {}".format(exc))

    if dry_run and not _interrupted:
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
    _install_sigint_handler()

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

    if _interrupted:
        sys.exit(130)   # standard exit code for Ctrl-C


if __name__ == "__main__":
    main()
