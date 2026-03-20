#!/cld/tools/python3.8.8/bin/python3.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    ic_cleanup.py <scan_root> [options]

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
        ancestor (str)  : regex matched against ANY component of the full
                          absolute path from filesystem root down to the
                          entry's parent (inclusive). Omit to match anywhere.
        desc     (str)  : human-readable label shown in output

    Rules are evaluated top-to-bottom; first match wins.
    Once a directory matches a rule it is NOT descended into.

not_current logic:
    A rule with level=NOT_CURRENT inspects all symlinks in the same directory
    whose name contains "current" (case-insensitive).  The resolved target
    basename is protected.

    name IN  protected  ->  tag [KEEP(CURR)]  -- never deleted
    name NOT protected  ->  tag [SAFE(NCUR)]  -- treated as SAFE / deletable
"""

import argparse
import os
import pwd
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
SAFE        = "Safe"        # ok to delete
CAUTION     = "Caution"     # delete old, keep newest
DANGER      = "Danger"      # manual confirm before deleting
PROTECTED   = "Protected"   # never delete
NOT_CURRENT = "Not-Current" # versioned dir: keep if pointed to by 'current' symlink

ALL_LEVELS = (SAFE, CAUTION, DANGER, PROTECTED, NOT_CURRENT)

# Sub-tags for the two NOT_CURRENT outcomes
_TAG_SAFE_NCUR  = "SAFE(NCUR)"   # matched NOT_CURRENT rule but NOT protected
_TAG_KEEP_CURR  = "KEEP(CURR)"   # matched NOT_CURRENT rule and IS protected

# Plain tags (file output, no ANSI)
_LEVEL_TAG_PLAIN = {
    SAFE:        "[SAFE    ]",
    CAUTION:     "[CAUTION ]",
    DANGER:      "[DANGER  ]",
    PROTECTED:   "[PROTECT ]",
    NOT_CURRENT: "[KEEP(CURR)]",  # only reached when actually kept
}

# Special plain overrides for the two NOT_CURRENT outcomes
_PLAIN_SAFE_NCUR = "[SAFE(NCUR)]"
_PLAIN_KEEP_CURR = "[KEEP(CURR)]"

# Colored tags (terminal output)
_LEVEL_TAG_COLOR = {
    SAFE:        _c("[SAFE    ]",  "green",  "bold"),
    CAUTION:     _c("[CAUTION ]",  "yellow", "bold"),
    DANGER:      _c("[DANGER  ]",  "red",    "bold"),
    PROTECTED:   _c("[PROTECT ]",  "cyan",   "bold"),
    NOT_CURRENT: _c("[KEEP(CURR)]","blue",   "bold"),
}

_COLOR_SAFE_NCUR = _c("[SAFE(NCUR)]", "green",  "bold")
_COLOR_KEEP_CURR = _c("[KEEP(CURR)]", "blue",   "bold")

# Levels eligible for deletion (SAFE covers both [SAFE] and [SAFE(NCUR)])
_DELETABLE = (SAFE, CAUTION)

LEVEL_MAP = {
    "safe":        SAFE,
    "caution":     CAUTION,
    "danger":      DANGER,
    "protected":   PROTECTED,
    "not_current": NOT_CURRENT,
}

# ===========================================================================
#  Internal sentinel to distinguish the two NOT_CURRENT outcomes
# ===========================================================================
_NCUR_SAFE = "__NCUR_SAFE__"  # deletable
_NCUR_KEEP = "__NCUR_KEEP__"  # protected


def _effective_level(internal):
    # type: (str) -> str
    """Map internal sentinel back to the public level constant."""
    if internal == _NCUR_SAFE:
        return SAFE
    if internal == _NCUR_KEEP:
        return NOT_CURRENT
    return internal


def _tag_plain(internal):
    # type: (str) -> str
    if internal == _NCUR_SAFE:
        return _PLAIN_SAFE_NCUR
    if internal == _NCUR_KEEP:
        return _PLAIN_KEEP_CURR
    return _LEVEL_TAG_PLAIN[internal]


def _tag_color(internal):
    # type: (str) -> str
    if internal == _NCUR_SAFE:
        return _COLOR_SAFE_NCUR
    if internal == _NCUR_KEEP:
        return _COLOR_KEEP_CURR
    return _LEVEL_TAG_COLOR[internal]


# ===========================================================================
#  Rule table -- THE ONLY PLACE TO EDIT RULES
#
#  Keys:
#    pattern  (str, required) : Python regex matched against entry basename
#    type     (str, required) : "f" | "d" | "fd"
#    level    (str, required) : SAFE / CAUTION / DANGER / PROTECTED / NOT_CURRENT
#    ancestor (str, optional) : Python regex matched against ANY component
#                               of the absolute path from / to entry's parent.
#    desc     (str, optional) : label shown in report
#
#  Rules evaluated top-to-bottom; first match wins.
#  Matched directories are always pruned (never descended into).
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
    # Example:
    #   MACRO/sram/
    #     000111/          -> [SAFE(NCUR)]  no symlink -> deletable
    #     000112/          -> [KEEP(CURR)]  current -> 000112 -> protected
    #     current -> 000112
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
#  Tests ancestor_re against every component of the absolute path from
#  filesystem root down to (not including) the entry basename itself.
# ===========================================================================
def has_ancestor_match(entry_abs, ancestor_re):
    # type: (Path, re.Pattern) -> bool
    for part in entry_abs.parts[:-1]:
        if ancestor_re.search(part):
            return True
    return False


# ===========================================================================
#  "current" symlink resolution  (case-insensitive, cached per directory)
# ===========================================================================
_current_cache = {}  # type: Dict[str, Set[str]]


def current_targets_in_dir(parent):
    # type: (Path) -> Set[str]
    targets = set()  # type: Set[str]
    try:
        for entry in os.scandir(str(parent)):
            if not entry.is_symlink():
                continue
            if "current" not in entry.name.lower():
                continue
            try:
                raw = os.readlink(entry.path)
                target = Path(raw) if os.path.isabs(raw) else parent / raw
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
#  Returns (internal_level, description) or None
# ===========================================================================
def classify(name, parent, is_dir):
    # type: (str, Path, bool) -> Optional[Tuple[str, str]]
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
            if name in get_current_targets(parent):
                return _NCUR_KEEP, desc
            return _NCUR_SAFE, desc

        return level, desc

    return None


# ===========================================================================
#  File owner helper
# ===========================================================================
def get_owner(path):
    # type: (Path) -> str
    try:
        uid = path.stat().st_uid
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)
    except OSError:
        return "?"


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
    """Calculate directory size using os.walk(followlinks=False) to avoid
    hanging on symlink loops."""
    total = 0
    try:
        for dirpath, _dirs, files in os.walk(str(path), followlinks=False):
            for fname in files:
                fpath = os.path.join(dirpath, fname)
                if os.path.islink(fpath):
                    continue
                try:
                    total += os.path.getsize(fpath)
                except OSError:
                    pass
    except PermissionError:
        pass
    return total


# Column widths (based on plain tags)
_TAG_WIDTH   = max(len(t) for t in list(_LEVEL_TAG_PLAIN.values()) +
                   [_PLAIN_SAFE_NCUR, _PLAIN_KEEP_CURR])
_OWNER_WIDTH = 12
_TYPE_WIDTH  = 1   # "F" or "D"

HEADER_PLAIN = "{:>12}  {:<16}  {:<{tw}}  {:<{ow}}  {}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "OWNER", "T", "PATH",
    tw=_TAG_WIDTH, ow=_OWNER_WIDTH,
)
SEP = "-" * 120


def fmt_row(size, mtime, internal, owner, ftype, abs_path, for_file=False):
    # type: (int, float, str, str, str, str, bool) -> str
    tag = _tag_plain(internal) if for_file else _tag_color(internal)
    return "{:>12}  {:<16}  {:<{tw}}  {:<{ow}}  {}  {}".format(
        human_size(size),
        fmt_mtime(mtime),
        tag,
        owner,
        ftype,
        abs_path,
        tw=_TAG_WIDTH,
        ow=_OWNER_WIDTH,
    )


# ===========================================================================
#  Progress line on stderr  (transient, written below result rows)
# ===========================================================================
_TERM_WIDTH = shutil.get_terminal_size((120, 24)).columns


def _progress(current_dir):
    # type: (str) -> None
    """Write a transient scanning indicator to stderr.
    Uses \\r so it stays on the current line and does NOT scroll the terminal,
    which means result rows printed above it are undisturbed."""
    if not _USE_COLOR:
        return
    label   = "Scanning: " + current_dir
    max_len = _TERM_WIDTH - 2
    if len(label) > max_len:
        label = "Scanning: ..." + current_dir[-(max_len - 13):]
    # \r returns to start of line; padding erases previous longer text
    sys.stderr.write("\r{:<{w}}".format(_c(label, "dim"), w=_TERM_WIDTH))
    sys.stderr.flush()


def _clear_progress():
    # type: () -> None
    if not _USE_COLOR:
        return
    sys.stderr.write("\r{}\r".format(" " * _TERM_WIDTH))
    sys.stderr.flush()


# ===========================================================================
#  emit: clear progress -> print result -> reprint progress
# ===========================================================================
def emit(line_term, line_file, fh, current_dir=""):
    # type: (str, str, object, str) -> None
    """Print a result row, then immediately reprint the progress line so it
    always appears at the bottom of visible output."""
    _clear_progress()
    print(line_term)
    if fh:
        fh.write(line_file + "\n")
    # Reprint progress below the freshly printed row
    if current_dir:
        _progress(current_dir)


# ===========================================================================
#  Interrupt handling
# ===========================================================================
_interrupted = False


def _handle_sigint(signum, frame):
    global _interrupted
    _interrupted = True
    _clear_progress()
    sys.stderr.write(
        _c("\n[INTERRUPTED] Ctrl-C caught -- "
           "stopping scan, printing partial results...\n", "yellow", "bold")
    )
    sys.stderr.flush()


def _install_sigint_handler():
    signal.signal(signal.SIGINT, _handle_sigint)


# ===========================================================================
#  Streaming scan
# ===========================================================================
def scan_and_print(root, level_filter, output_fh):
    # type: (Path, Optional[Set[str]], object) -> List[Tuple]
    """
    Each result tuple: (size, mtime, effective_level, internal_level, owner, ftype, abs_path)
    """
    root_real = Path(os.path.realpath(str(root)))

    header_term = _c(HEADER_PLAIN, "bold")
    _clear_progress()
    print(header_term)
    print(SEP)
    if output_fh:
        output_fh.write(HEADER_PLAIN + "\n")
        output_fh.write(SEP + "\n")

    results  = []   # type: List[Tuple]
    counts   = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]
    cur_dir  = ""   # track current dir for progress reprint after emit

    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        if _interrupted:
            dirnames[:] = []
            break

        dp      = Path(dirpath)
        cur_dir = dirpath
        _progress(cur_dir)

        # --- directories ---
        for dname in list(dirnames):
            if _interrupted:
                break

            full = dp / dname
            if full.is_symlink():
                continue

            result = classify(dname, dp, is_dir=True)
            if result is None:
                continue

            internal, _desc = result
            effective        = _effective_level(internal)

            # Always prune -- never descend into matched dirs
            dirnames.remove(dname)

            if level_filter and effective not in level_filter:
                continue

            try:
                st    = full.stat()
                size  = dir_total_size(full)
                mt    = st.st_mtime
                owner = get_owner(full)
            except PermissionError:
                continue

            abs_path = str(root_real / full.relative_to(root))
            row_term = fmt_row(size, mt, internal, owner, "D", abs_path, for_file=False)
            row_file = fmt_row(size, mt, internal, owner, "D", abs_path, for_file=True)
            emit(row_term, row_file, output_fh, cur_dir)

            results.append((size, mt, effective, internal, owner, "D", Path(abs_path)))
            counts[effective] += 1

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

            internal, _desc = result
            effective        = _effective_level(internal)

            if level_filter and effective not in level_filter:
                continue

            try:
                st    = full.stat()
                size  = st.st_size
                mt    = st.st_mtime
                owner = get_owner(full)
            except PermissionError:
                continue

            abs_path = str(root_real / full.relative_to(root))
            row_term = fmt_row(size, mt, internal, owner, "F", abs_path, for_file=False)
            row_file = fmt_row(size, mt, internal, owner, "F", abs_path, for_file=True)
            emit(row_term, row_file, output_fh, cur_dir)

            results.append((size, mt, effective, internal, owner, "F", Path(abs_path)))
            counts[effective] += 1

    _clear_progress()

    # --- summary ---
    total_size  = sum(r[0] for r in results)
    total_count = len(results)
    partial     = "  [PARTIAL - scan interrupted]" if _interrupted else ""

    print(SEP)
    if output_fh:
        output_fh.write(SEP + "\n")

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
    print(_c(summary, "bold"))
    if output_fh:
        output_fh.write(summary + "\n")

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
    print("\n{} {} items eligible (Safe + Caution only):\n".format(
        tag_label, len(deletable)))

    for _size, _mt, effective, internal, _owner, _ftype, path in deletable:
        if _interrupted:
            print(_c("  [INTERRUPTED] delete aborted.", "yellow"))
            break
        print("  {}  {}  {}".format(tag_label, _tag_color(internal), path))
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

    # Build level filter using public level constants
    level_filter = None  # type: Optional[Set[str]]
    if args.level:
        level_filter = {LEVEL_MAP[l] for l in args.level}

    root_real = Path(os.path.realpath(str(root)))
    print("Scanning: {}\n".format(_c(str(root_real), "bold")))

    output_fh = None
    if args.output:
        try:
            output_fh = open(args.output, "w", encoding="utf-8")
            output_fh.write("# IC Cleanup report\n")
            output_fh.write("# Root  : {}\n".format(root_real))
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
