#!/cld/tools/python3.8.8/bin/python3.8.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    python ic_cleanup.py <scan_root> [options]

Options:
    --output FILE        Write results to a file in addition to stdout
    --delete             Actually delete files (default: dry-run, list only)
    --level LEVEL [...]  Show only specific risk level(s):
                           safe | caution | danger | protected | not_current

Rule format (RULES list):
    Each rule is a dict with the following keys:

    Required:
        pattern  (str)  : regex matched against the entry basename
        type     (str)  : "f" = file only, "d" = directory only, "fd" = both
        level    (str)  : SAFE / CAUTION / DANGER / PROTECTED / NOT_CURRENT

    Optional:
        ancestor (str)  : regex matched against ANY component of the full path
                          from filesystem root up to (and including) the scan
                          root, plus every component below it down to the
                          entry's parent.  Omit to match regardless of location.
        desc     (str)  : human-readable label shown in output

    Rules are evaluated top-to-bottom; first match wins.
    Once a directory matches a rule it is NOT descended into.

not_current logic:
    When a rule carries level=NOT_CURRENT the tool looks at all symlinks
    whose name contains "current" (case-insensitive) that live in the SAME
    directory as the candidate entry.  The resolved target basename is
    collected into a protected set.

    candidate name IN protected  ->  shown as NOT_CURRENT / [KEEP] (never deleted)
    candidate name NOT protected ->  shown as SAFE / [SAFE]        (eligible for deletion)
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


def _c(text, *codes):
    # type: (str, str) -> str
    if not _USE_COLOR:
        return text
    prefix = "".join(_ANSI.get(c, "") for c in codes)
    return "{}{}{}".format(prefix, text, _ANSI["reset"])


# ===========================================================================
#  Risk level constants
# ===========================================================================
SAFE        = "Safe"           # was: Low Risk      -- ok to delete
CAUTION     = "Caution"        # was: Medium Risk   -- delete old, keep new
DANGER      = "Danger"         # was: High Risk     -- manual confirm needed
PROTECTED   = "Protected"      # was: DON'T TOUCH   -- never delete
NOT_CURRENT = "Not-Current"    # versioned dir; effective level depends on symlink

ALL_LEVELS = (SAFE, CAUTION, DANGER, PROTECTED, NOT_CURRENT)

_LEVEL_TAG_PLAIN = {
    SAFE:        "[SAFE    ]",
    CAUTION:     "[CAUTION ]",
    DANGER:      "[DANGER  ]",
    PROTECTED:   "[PROTECT ]",
    NOT_CURRENT: "[KEEP    ]",
}

_LEVEL_TAG_COLOR = {
    SAFE:        _c("[SAFE    ]", "green",  "bold"),
    CAUTION:     _c("[CAUTION ]", "yellow", "bold"),
    DANGER:      _c("[DANGER  ]", "red",    "bold"),
    PROTECTED:   _c("[PROTECT ]", "cyan",   "bold"),
    NOT_CURRENT: _c("[KEEP    ]", "blue",   "bold"),
}


def level_tag(level, for_file=False):
    # type: (str, bool) -> str
    return _LEVEL_TAG_PLAIN[level] if for_file else _LEVEL_TAG_COLOR[level]


LEVEL_MAP = {
    "safe":        SAFE,
    "caution":     CAUTION,
    "danger":      DANGER,
    "protected":   PROTECTED,
    "not_current": NOT_CURRENT,
}

# Levels that are eligible for deletion
_DELETABLE = (SAFE, CAUTION)

# ===========================================================================
#  Rule table
#
#  Keys:
#    pattern  (str, required) : Python regex matched against entry basename
#    type     (str, required) : "f" | "d" | "fd"
#    level    (str, required) : SAFE / CAUTION / DANGER / PROTECTED / NOT_CURRENT
#    ancestor (str, optional) : Python regex; matched against EVERY path
#                               component from filesystem root all the way
#                               down to the entry's parent (inclusive).
#                               Omit to match regardless of location.
#    desc     (str, optional) : label shown in report
#
#  Rules are evaluated top-to-bottom; first match wins.
#  Matched directories are always pruned (never descended into).
#
#  not_current:
#    Siblings whose name is the resolved target of any symlink whose name
#    contains "current" (case-insensitive) in the same directory are shown
#    as NOT_CURRENT / [KEEP] and are never deleted.
#    All other pattern-matching siblings become SAFE (deletable).
# ===========================================================================
RULES = [  # type: List[Dict]

    # --- Safe: simulation waveforms ---
    {"pattern": r".*\.fsdb$",               "type": "f",  "level": SAFE,      "desc": "sim waveform"},
    {"pattern": r".*\.vcd$",                "type": "f",  "level": SAFE,      "desc": "sim waveform"},
    {"pattern": r".*\.shm$",                "type": "f",  "level": SAFE,      "desc": "sim waveform"},
    {"pattern": r".*\.vpd$",                "type": "f",  "level": SAFE,      "desc": "sim waveform"},

    # --- Safe: compile / run cache ---
    {"pattern": r".*INCA_libs$",            "type": "d",  "level": SAFE,      "desc": "compile cache dir"},
    {"pattern": r".*xcelium\.d$",           "type": "d",  "level": SAFE,      "desc": "compile cache dir"},
    {"pattern": r"^csrc$",                  "type": "d",  "level": SAFE,      "desc": "compile cache dir"},
    {"pattern": r"^simv$",                  "type": "f",  "level": SAFE,      "desc": "sim binary"},
    {"pattern": r"^simv\.daidir$",          "type": "d",  "level": SAFE,      "desc": "sim binary dir"},

    # --- Safe: log files ---
    {"pattern": r".*\.log$",                "type": "f",  "level": SAFE,      "desc": "log file"},
    {"pattern": r".*sim\.log$",             "type": "f",  "level": SAFE,      "desc": "sim log"},

    # --- Safe: editor swap ---
    {"pattern": r".*\.swp$",                "type": "f",  "level": SAFE,      "desc": "vim swap file"},

    # --- Safe: crte temp files ---
    {"pattern": r"^crte_.*\.txt$",          "type": "f",  "level": SAFE,      "desc": "crte temp file"},

    # --- Safe: work_restore directory ---
    {"pattern": r"^work_restore$",          "type": "d",  "level": SAFE,      "desc": "work restore dir"},

    # --- Safe: STA workspace ---
    {"pattern": r"^DMSA_output_",           "type": "d",  "level": SAFE,      "desc": "STA workspace"},
    {"pattern": r"^PT_output_",             "type": "d",  "level": SAFE,      "desc": "STA workspace"},
    {"pattern": r".*PT_session$",           "type": "d",  "level": SAFE,      "desc": "PT session dir"},
    {"pattern": r".*PC_session$",           "type": "d",  "level": SAFE,      "desc": "PC session dir"},
    {"pattern": r".*TWK_session$",          "type": "d",  "level": SAFE,      "desc": "TWK session dir"},
    {"pattern": r"^save_bf_session$",       "type": "d",  "level": SAFE,      "desc": "STA patch record"},
    {"pattern": r"^save_af_session$",       "type": "d",  "level": SAFE,      "desc": "STA patch record"},

    # --- Safe: misc tool temp ---
    {"pattern": r".*\.power\.list$",        "type": "f",  "level": SAFE,      "desc": "PTPX temp"},
    {"pattern": r".*\.timing$",             "type": "f",  "level": SAFE,      "desc": "PTPX temp"},
    {"pattern": r".*checkpoint$",           "type": "fd", "level": SAFE,      "desc": "LEC checkpoint"},
    {"pattern": r".*FM_WORK$",              "type": "d",  "level": SAFE,      "desc": "Formality work dir"},
    {"pattern": r".*FM_INFO$",              "type": "d",  "level": SAFE,      "desc": "Formality info dir"},
    {"pattern": r".*\.fss$",                "type": "f",  "level": SAFE,      "desc": "Formality aux"},
    {"pattern": r".*\.svf$",                "type": "f",  "level": SAFE,      "desc": "Formality aux"},
    {"pattern": r"^core\.",                 "type": "f",  "level": SAFE,      "desc": "system crash dump"},

    # --- Safe: special cases ---
    {"pattern": r"^violation_report\.rpt$", "type": "f",  "level": SAFE,      "desc": "sg_sdc violation report"},
    {"pattern": r"^vcst_",                  "type": "fd", "level": SAFE,      "desc": "VCSG_lint temp"},
    {"pattern": r"^vcst_rtdb$",             "type": "d",  "level": SAFE,      "desc": "VCSG_lint rtdb"},
    {"pattern": r"^vcst_rtdb\.bak$",        "type": "d",  "level": SAFE,      "desc": "VCSG_lint rtdb backup"},
    {"pattern": r"^idbs$",                  "type": "d",  "level": SAFE,      "desc": "nvtClkExp temp"},
    {"pattern": r"^vsi\.tar\.lz4$",         "type": "f",  "level": SAFE,      "desc": "nvtCHK temp"},

    # --- Caution: keep newest, delete old ---
    {"pattern": r".*\.ddc$",                "type": "f",  "level": CAUTION,   "desc": "synthesis snapshot"},
    {"pattern": r".*\.saif$",               "type": "f",  "level": CAUTION,   "desc": "power activity file"},
    {"pattern": r".*\.bit$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.bin$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.mcs$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.pat$",                "type": "f",  "level": CAUTION,   "desc": "DFT pattern"},
    {"pattern": r"^PC_output",              "type": "d",  "level": CAUTION,   "desc": "P&R intermediate layout"},
    {"pattern": r".*\.spef$",               "type": "f",  "level": CAUTION,   "desc": "P&R parasitics"},
    {"pattern": r"^lint_cpdb$",             "type": "d",  "level": CAUTION,   "desc": "VCSG_lint cpdb"},

    # --- Danger: manual confirm before deleting ---
    {"pattern": r".*\.v$",                  "type": "f",  "level": DANGER,    "desc": "netlist/RTL (manual confirm)"},
    {"pattern": r".*\.vg$",                 "type": "f",  "level": DANGER,    "desc": "gate-level netlist"},
    {"pattern": r"^report_qor\.rpt$",       "type": "f",  "level": DANGER,    "desc": "STA signoff report"},
    {"pattern": r"^summary_.*\.rpt$",       "type": "f",  "level": DANGER,    "desc": "STA signoff summary"},
    {"pattern": r".*_final\.gds$",          "type": "f",  "level": DANGER,    "desc": "P&R final GDS"},
    {"pattern": r"^ptpx_final",             "type": "fd", "level": DANGER,    "desc": "power signoff"},

    # --- Not-Current: versioned snapshot dirs under any MACRO ancestor ---
    #
    # Example structure:
    #   MACRO/sram/
    #     000111/          -> SAFE    (no symlink points here -> deletable)
    #     000112/          -> KEEP    (current -> 000112 -> protected)
    #     current -> 000112
    #
    # 'ancestor' is matched against every path component all the way from
    # filesystem root to the entry's parent, so this works whether the user
    # scans from /proj, /proj/MACRO, or /proj/MACRO/sram.
    {
        "pattern":  r"^\d{6}$",
        "type":     "d",
        "level":    NOT_CURRENT,
        "ancestor": r".*MACRO.*",
        "desc":     "MACRO versioned snapshot",
    },

    # --- Protected: never delete ---
    {"pattern": r".*\.sv$",                 "type": "f",  "level": PROTECTED, "desc": "RTL source"},
    {"pattern": r".*\.sdc$",                "type": "f",  "level": PROTECTED, "desc": "timing constraints"},
    {"pattern": r"^Makefile$",              "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.prj$",                "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.sgdc$",               "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.tcl$",                "type": "f",  "level": PROTECTED, "desc": "flow script"},
    {"pattern": r".*\.py$",                 "type": "f",  "level": PROTECTED, "desc": "flow script"},
    {"pattern": r".*\.pl$",                 "type": "f",  "level": PROTECTED, "desc": "flow script"},
]  # type: List[Dict]

# Pre-compile all regexes once at import time
for _r in RULES:
    _r["_pat_re"]      = re.compile(_r["pattern"])
    _r["_ancestor_re"] = re.compile(_r["ancestor"]) if _r.get("ancestor") else None


# ===========================================================================
#  Ancestor path check
#  Matches the regex against EVERY component of the absolute path from
#  filesystem root all the way down to the entry's immediate parent.
#  This means it works correctly regardless of where the scan root is.
# ===========================================================================
def has_ancestor_match(entry_abs, ancestor_re):
    # type: (Path, re.Pattern) -> bool
    # entry_abs.parts includes every component including the entry name itself
    # We check all parts except the last one (the entry name).
    parts = entry_abs.parts[:-1]   # everything above the entry
    for part in parts:
        if ancestor_re.search(part):
            return True
    return False


# ===========================================================================
#  "current" symlink resolution  (case-insensitive, cached per directory)
# ===========================================================================
_current_cache = {}  # type: Dict[str, Set[str]]


def current_targets_in_dir(parent):
    # type: (Path) -> Set[str]
    """
    Return the set of real directory basenames that any symlink whose name
    contains 'current' (case-insensitive) inside `parent` resolves to.
    Broken symlinks and symlinks pointing to files are ignored.
    """
    targets = set()  # type: Set[str]
    try:
        for entry in os.scandir(str(parent)):
            if not entry.is_symlink():
                continue
            if "current" not in entry.name.lower():
                continue
            try:
                raw_target = os.readlink(entry.path)
                target = Path(raw_target)
                if not target.is_absolute():
                    target = parent / target
                # Resolve without following symlinks infinitely:
                # use os.path.realpath which is available in 3.8
                resolved = Path(os.path.realpath(str(target)))
                if resolved.is_dir():
                    targets.add(resolved.name)
            except OSError:
                pass
    except PermissionError:
        pass
    return targets


def get_current_targets(parent):
    # type: (Path) -> Set[str]
    key = str(parent)
    if key not in _current_cache:
        _current_cache[key] = current_targets_in_dir(parent)
    return _current_cache[key]


# ===========================================================================
#  Classification
# ===========================================================================
def classify(name, parent, is_dir):
    # type: (str, Path, bool) -> Optional[Tuple[str, str]]
    """
    Return (effective_level, description) or None if no rule matches.

    ancestor check : every path component from filesystem root to the
                     entry's parent is tested against rule['ancestor'].

    not_current    : effective level is NOT_CURRENT if this entry's name is
                     the resolved target of a 'current*' symlink in parent,
                     otherwise SAFE (deletable).
    """
    entry_type = "d" if is_dir else "f"
    entry_abs  = parent / name

    for rule in RULES:
        if entry_type not in rule["type"]:
            continue
        if not rule["_pat_re"].search(name):
            continue
        if rule["_ancestor_re"] is not None:
            if not has_ancestor_match(entry_abs, rule["_ancestor_re"]):
                continue

        level = rule["level"]
        desc  = rule.get("desc", "")

        if level == NOT_CURRENT:
            protected = get_current_targets(parent)
            if name in protected:
                return NOT_CURRENT, desc
            return SAFE, desc

        return level, desc

    return None


# ===========================================================================
#  Formatting helpers
# ===========================================================================
def human_size(nbytes):
    # type: (float) -> str
    if nbytes == 0:
        return "0.0 B"
    size = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return "{:.1f} {}".format(size, unit)
        size /= 1024.0
    return "{:.1f} PB".format(size)


def fmt_mtime(ts):
    # type: (float) -> str
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def dir_total_size(path):
    # type: (Path) -> int
    """
    Calculate directory size using os.walk (followlinks=False) to avoid
    hanging on symlink loops.  os.walk(followlinks=False) is used instead.
    """
    total = 0
    try:
        for dirpath, _dirs, files in os.walk(str(path), followlinks=False):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                # skip symlinks to avoid double-counting and loops
                if os.path.islink(fpath):
                    continue
                try:
                    total += os.path.getsize(fpath)
                except OSError:
                    pass
    except PermissionError:
        pass
    return total


_TAG_WIDTH   = len("[CAUTION ]")   # longest plain tag
HEADER_PLAIN = "{:>12}  {:<16}  {:<{w}}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "PATH", w=_TAG_WIDTH
)
SEP = "-" * 110


def fmt_row(size, mtime, level, rel_path, for_file=False):
    # type: (int, float, str, str, bool) -> str
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


def _progress(current_dir):
    # type: (str) -> None
    if not _USE_COLOR:
        return
    max_len = _TERM_WIDTH - 2
    label   = "Scanning: " + current_dir
    if len(label) > max_len:
        label = "Scanning: ..." + current_dir[-(max_len - 13):]
    sys.stderr.write("\r{:<{w}}".format(_c(label, "dim"), w=_TERM_WIDTH))
    sys.stderr.flush()


def _clear_progress():
    # type: () -> None
    if not _USE_COLOR:
        return
    sys.stderr.write("\r{}\r".format(" " * _TERM_WIDTH))
    sys.stderr.flush()


# ===========================================================================
#  emit: stdout + optional file handle
# ===========================================================================
def emit(line_term, line_file, fh):
    # type: (str, str, object) -> None
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
    sys.stderr.write(
        _c("\n[INTERRUPTED] Ctrl-C caught -- stopping scan, printing partial results...\n",
           "yellow", "bold")
    )
    sys.stderr.flush()


def _install_sigint_handler():
    signal.signal(signal.SIGINT, _handle_sigint)


# ===========================================================================
#  Streaming scan
# ===========================================================================
def scan_and_print(root, level_filter, output_fh):
    # type: (Path, Optional[Set[str]], object) -> List[Tuple[int, float, str, Path]]

    header_term = _c(HEADER_PLAIN, "bold")
    emit(header_term, HEADER_PLAIN, output_fh)
    emit(SEP, SEP, output_fh)

    results = []   # type: List[Tuple[int, float, str, Path]]
    counts  = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]

    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        if _interrupted:
            dirnames[:] = []   # stop os.walk descending further
            break

        dp = Path(dirpath)
        _progress(dirpath)

        # --- directories ---
        for dname in list(dirnames):
            if _interrupted:
                break

            full = dp / dname

            # skip symlinks
            if full.is_symlink():
                continue

            result = classify(dname, dp, is_dir=True)
            if result is None:
                continue

            level, _desc = result

            # ALWAYS prune matched dirs regardless of level_filter
            # so we never descend into them
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
    partial     = "  [PARTIAL - scan interrupted]" if _interrupted else ""

    emit(SEP, SEP, output_fh)
    summary = (
        "Total {} items  |  "
        "Safe: {}  Caution: {}  Danger: {}  Protected: {}  Keep: {}  |  "
        "Est. size: {}{}"
    ).format(
        total_count,
        counts[SAFE], counts[CAUTION], counts[DANGER],
        counts[PROTECTED], counts[NOT_CURRENT],
        human_size(total_size), partial,
    )
    emit(_c(summary, "bold"), summary, output_fh)

    return results


# ===========================================================================
#  Delete  (dry-run by default)
# ===========================================================================
def do_delete(results, dry_run):
    # type: (List[Tuple], bool) -> None
    deletable = [r for r in results if r[2] in _DELETABLE]

    if not deletable:
        print("\nNothing to delete. (Danger / Protected / Keep are never auto-deleted.)")
        return

    tag_label = (
        _c("[DRY-RUN]", "yellow", "bold") if dry_run
        else _c("[DELETE] ", "red",    "bold")
    )
    print("\n{} {} items eligible (Safe + Caution only):\n".format(tag_label, len(deletable)))

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
def build_parser():
    # type: () -> argparse.ArgumentParser
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
        help="Actually delete Safe/Caution items (default: dry-run)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output (one or more): safe caution danger protected not_current")
    return p


def main():
    # type: () -> None
    _install_sigint_handler()

    args = build_parser().parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print("ERROR: directory not found: {}".format(root), file=sys.stderr)
        sys.exit(1)

    level_filter = None  # type: Optional[Set[str]]
    if args.level:
        level_filter = {LEVEL_MAP[l] for l in args.level}

    print("Scanning: {}\n".format(_c(str(root), "bold")))

    output_fh = None
    if args.output:
        try:
            output_fh = open(args.output, "w", encoding="utf-8")
            output_fh.write("# IC Cleanup report\n")
            output_fh.write("# Root  : {}\n".format(root))
            output_fh.write("# Date  : {}\n".format(
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            output_fh.write("# Filter: {}\n\n".format(
                ", ".join(args.level) if args.level else "all"))
        except OSError as exc:
            print("ERROR: cannot open output file: {}".format(exc), file=sys.stderr)
            sys.exit(1)

    try:
        results = scan_and_print(root, level_filter, output_fh)
    finally:
        if output_fh:
            output_fh.close()
            print("\nReport written to: {}".format(
                _c(str(Path(args.output).resolve()), "cyan")))

    if not results:
        print("\nNo matching files found.")
        return

    print()
    do_delete(results, dry_run=not args.delete)

    if _interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
