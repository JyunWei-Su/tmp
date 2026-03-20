#!/cld/tools/python3.8.8/bin/python3.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    ic_cleanup.py <scan_root> [options]

Options:
    --log-trace FILE     Write scan results to FILE  (.gz extension = gzip compressed)
    --log-delete FILE    Write delete actions to FILE (.gz extension = gzip compressed)
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
import gzip
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

# Internal sentinels for the two NOT_CURRENT outcomes
_NCUR_SAFE = "__NCUR_SAFE__"  # matched NOT_CURRENT rule, NOT protected -> deletable
_NCUR_KEEP = "__NCUR_KEEP__"  # matched NOT_CURRENT rule, IS  protected -> keep

# ---------------------------------------------------------------------------
#  Tag strings -- ALL padded to the SAME fixed width so columns line up.
#  Width = len("[SAFE(NCUR)]") = 12
# ---------------------------------------------------------------------------
_TW = 12   # tag width (characters, excluding surrounding spaces in the column)

_PLAIN = {
    SAFE:        "[SAFE    ]  ",   # 12 chars
    CAUTION:     "[CAUTION ]  ",
    DANGER:      "[DANGER  ]  ",
    PROTECTED:   "[PROTECT ]  ",
    NOT_CURRENT: "[KEEP(CURR)]",   # NOT_CURRENT shown as keep  (12 chars)
    _NCUR_SAFE:  "[SAFE(NCUR)]",
    _NCUR_KEEP:  "[KEEP(CURR)]",
}

# Verify all plain tags are the same width at import time
_tag_lengths = {k: len(v) for k, v in _PLAIN.items()}
assert len(set(_tag_lengths.values())) == 1, \
    "Tag width mismatch: {}".format(_tag_lengths)

_COLOR = {
    SAFE:        _c(_PLAIN[SAFE],        "green",  "bold"),
    CAUTION:     _c(_PLAIN[CAUTION],     "yellow", "bold"),
    DANGER:      _c(_PLAIN[DANGER],      "red",    "bold"),
    PROTECTED:   _c(_PLAIN[PROTECTED],   "cyan",   "bold"),
    NOT_CURRENT: _c(_PLAIN[NOT_CURRENT], "blue",   "bold"),
    _NCUR_SAFE:  _c(_PLAIN[_NCUR_SAFE],  "green",  "bold"),
    _NCUR_KEEP:  _c(_PLAIN[_NCUR_KEEP],  "blue",   "bold"),
}

# Levels eligible for deletion
_DELETABLE = (SAFE, CAUTION)

LEVEL_MAP = {
    "safe":        SAFE,
    "caution":     CAUTION,
    "danger":      DANGER,
    "protected":   PROTECTED,
    "not_current": NOT_CURRENT,
}


def _effective_level(internal):
    # type: (str) -> str
    if internal == _NCUR_SAFE:
        return SAFE
    if internal == _NCUR_KEEP:
        return NOT_CURRENT
    return internal


def _tag_plain(internal):
    # type: (str) -> str
    return _PLAIN[internal]


def _tag_color(internal):
    # type: (str) -> str
    return _COLOR[internal]


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
    # Pattern matches 6-digit prefix names (e.g. 000111, 000112_patch).
    # The sibling whose name is the resolved target of any "current*" symlink
    # (case-insensitive) is shown as [KEEP(CURR)]; all others as [SAFE(NCUR)].
    {
        "pattern":  r"^\d{6}.*$",
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
#  Classification  ->  (internal_sentinel, description) or None
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
#  File owner
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
    """Recursively calculate directory size.

    Uses a manual stack-based scandir loop instead of os.walk so that
    _interrupted is checked at every Python-level iteration.  This means
    Ctrl-C is honoured within one entry's worth of latency rather than
    waiting for the entire C-level readdir() batch to finish.

    Returns -1 if interrupted before completion.
    """
    total   = 0
    stack   = [str(path)]
    while stack:
        if _interrupted:
            return -1
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if _interrupted:
                        return -1
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += st.st_size
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass
    return total


# ---------------------------------------------------------------------------
#  Column layout
#  All plain tags are the same width (enforced by the assert above).
#  We use that width for the LEVEL column header too.
# ---------------------------------------------------------------------------
_TAG_COL_W   = len(list(_PLAIN.values())[0])   # e.g. 12
_OWNER_WIDTH = 12

HEADER_PLAIN = "{:>12}  {:<16}  {:<{tw}}  {:<{ow}}  {:<4}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "OWNER", "TYPE", "PATH",
    tw=_TAG_COL_W, ow=_OWNER_WIDTH,
)
SEP = "-" * 120


def fmt_row(size, mtime, internal, owner, ftype, abs_path, for_file=False):
    # type: (int, float, str, str, str, str, bool) -> str
    tag = _tag_plain(internal) if for_file else _tag_color(internal)
    ftype_str = "DIR " if ftype == "D" else "FILE"
    return "{:>12}  {:<16}  {}  {:<{ow}}  {:<4}  {}".format(
        human_size(size),
        fmt_mtime(mtime),
        tag,
        owner,
        ftype_str,
        abs_path,
        ow=_OWNER_WIDTH,
    )


# ===========================================================================
#  Progress line on stderr  (transient, reprinted after each result row)
# ===========================================================================
_TERM_WIDTH = shutil.get_terminal_size((120, 24)).columns


def _progress(current_dir):
    # type: (str) -> None
    if not _USE_COLOR:
        return
    label   = "Scanning: " + current_dir
    max_len = _TERM_WIDTH - 2
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
#  Log file helpers
#  Supports plain text and gzip (.gz suffix) with line-by-line flushing
#  so the file is always up-to-date even if the process is interrupted.
# ===========================================================================
def open_log(path):
    # type: (str) -> object
    """Open a log file for line-by-line text writing.

    If the path ends with .gz the file is gzip-compressed.
    We construct the GzipFile manually (mtime=0) so the output is
    deterministic and compatible with vim's gzip.vim plugin and standard
    gunzip / zcat tools.  The TextIOWrapper on top provides a .write(str)
    interface with UTF-8 encoding.
    """
    if path.endswith(".gz"):
        import io
        raw = open(path, "wb")
        gz  = gzip.GzipFile(filename="", mode="wb", compresslevel=6,
                             fileobj=raw, mtime=0)
        return io.TextIOWrapper(gz, encoding="utf-8")
    return open(path, "w", encoding="utf-8")


def _write_fh(fh, line):
    # type: (object, str) -> None
    """Write a line and flush immediately so on-disk content stays current."""
    if fh is not None:
        fh.write(line + "\n")          # type: ignore[union-attr]
        fh.flush()                     # type: ignore[union-attr]


def emit_row(line_term, line_plain, scan_fh, cur_dir):
    # type: (str, str, object, str) -> None
    """Print result row to stdout + scan log, then reprint progress."""
    _clear_progress()
    print(line_term)
    _write_fh(scan_fh, line_plain)
    if cur_dir:
        _progress(cur_dir)


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
def scan_and_print(root, level_filter, scan_fh, trace_path):
    # type: (Path, Optional[Set[str]], object, str) -> List[Tuple]
    """
    Result tuples: (size, mtime, effective_level, internal, owner, ftype, abs_path)
    trace_path: display path for the log status line (empty string = no log)
    """
    root_real = Path(os.path.realpath(str(root)))

    _clear_progress()
    print(_c(HEADER_PLAIN, "bold"))
    print(SEP)
    _write_fh(scan_fh, HEADER_PLAIN)
    _write_fh(scan_fh, SEP)

    # Always show log path status (even when no log file is used)
    if trace_path:
        print(_c("  log-trace : {}".format(trace_path), "dim"))
    else:
        print(_c("  log-trace : (none)", "dim"))
    print()

    results = []   # type: List[Tuple]
    counts  = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]
    cur_dir = ""

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
            effective = _effective_level(internal)

            # Always prune -- never descend into matched dirs
            dirnames.remove(dname)

            if level_filter and effective not in level_filter:
                continue

            if _interrupted:          # don't start expensive size calc after Ctrl-C
                break

            try:
                st    = full.stat()
                size  = dir_total_size(full)
                if size == -1:        # aborted mid-way by Ctrl-C
                    break
                mt    = st.st_mtime
                owner = get_owner(full)
            except PermissionError:
                continue

            abs_path = str(root_real / full.relative_to(root))
            emit_row(
                fmt_row(size, mt, internal, owner, "D", abs_path, for_file=False),
                fmt_row(size, mt, internal, owner, "D", abs_path, for_file=True),
                scan_fh, cur_dir,
            )
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
            effective = _effective_level(internal)

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
            emit_row(
                fmt_row(size, mt, internal, owner, "F", abs_path, for_file=False),
                fmt_row(size, mt, internal, owner, "F", abs_path, for_file=True),
                scan_fh, cur_dir,
            )
            results.append((size, mt, effective, internal, owner, "F", Path(abs_path)))
            counts[effective] += 1

    _clear_progress()

    # --- summary ---
    total_size  = sum(r[0] for r in results)
    total_count = len(results)
    partial     = "  [PARTIAL - scan interrupted]" if _interrupted else ""

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

    print(SEP)
    print(_c(summary, "bold"))
    _write_fh(scan_fh, SEP)
    _write_fh(scan_fh, summary)

    return results


# ===========================================================================
#  Delete  (dry-run by default)
# ===========================================================================
def do_delete(results, dry_run, delete_fh, delete_path):
    # type: (List[Tuple], bool, object, str) -> None
    """
    delete_fh   : open file handle for the delete log, or None.
    delete_path : display path for the log status line (empty string = no log)
    The delete log is written in plain text (no ANSI codes), flushed per line.
    """
    deletable = [r for r in results if r[2] in _DELETABLE]

    if not deletable:
        msg = "\nNothing to delete. (Danger / Protected / Keep are never auto-deleted.)"
        print(msg)
        _write_fh(delete_fh, msg)
        return

    mode        = "DRY-RUN" if dry_run else "DELETE"
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag_term    = _c("[{}]".format(mode), "yellow" if dry_run else "red", "bold")
    tag_plain   = "[{}]".format(mode)

    header_msg  = "\n{} {} items eligible (Safe + Caution only):".format(
        tag_plain, len(deletable))
    print("\n{}  {} items eligible (Safe + Caution only):".format(
        tag_term, len(deletable)))

    # Always show delete log path status
    if delete_path:
        print(_c("  log-delete: {}".format(delete_path), "dim"))
    else:
        print(_c("  log-delete: (none)", "dim"))
    print()

    _write_fh(delete_fh, "# IC Cleanup -- delete log")
    _write_fh(delete_fh, "# Date : {}".format(ts))
    _write_fh(delete_fh, "# Mode : {}".format(mode))
    _write_fh(delete_fh, header_msg)
    _write_fh(delete_fh, SEP)
    _write_fh(delete_fh, HEADER_PLAIN)
    _write_fh(delete_fh, SEP)

    for _size, _mt, effective, internal, owner, ftype, path in deletable:
        if _interrupted:
            interrupted_msg = "  [INTERRUPTED] delete aborted."
            print(_c(interrupted_msg, "yellow"))
            _write_fh(delete_fh, interrupted_msg)
            break

        row_plain = fmt_row(_size, _mt, internal, owner, ftype, str(path), for_file=True)
        row_term  = fmt_row(_size, _mt, internal, owner, ftype, str(path), for_file=False)

        status = "OK"
        if not dry_run:
            try:
                if path.is_dir():
                    shutil.rmtree(str(path))
                else:
                    path.unlink()
            except Exception as exc:
                status = "ERROR: {}".format(exc)

        print("  {}  {}".format(tag_term,  row_term))
        if status != "OK":
            err_msg = "             {}".format(status)
            print(_c(err_msg, "red"))
            _write_fh(delete_fh, row_plain + "  -> " + status)
        else:
            _write_fh(delete_fh, row_plain)

    _write_fh(delete_fh, SEP)
    if dry_run and not _interrupted:
        hint = "  (Add --delete to actually remove the files above.)"
        print("\n" + hint)
        _write_fh(delete_fh, hint)


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
    p.add_argument("--log-trace", metavar="FILE", default=None,
        dest="log_trace",
        help="Write scan results to FILE (use .gz suffix for gzip compression)")
    p.add_argument("--log-delete", metavar="FILE", default=None,
        dest="log_delete",
        help="Write delete actions to FILE (use .gz suffix for gzip compression)")
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

    root_real = Path(os.path.realpath(str(root)))
    print("Scanning: {}\n".format(_c(str(root_real), "bold")))

    # --- open scan (trace) log ---
    scan_fh    = None
    trace_path = ""
    if args.log_trace:
        trace_path = str(Path(args.log_trace).resolve())
        try:
            scan_fh = open_log(args.log_trace)
            scan_fh.write("# IC Cleanup -- scan trace log\n")  # type: ignore
            scan_fh.write("# Root  : {}\n".format(root_real))  # type: ignore
            scan_fh.write("# Date  : {}\n".format(            # type: ignore
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            scan_fh.write("# Filter: {}\n\n".format(          # type: ignore
                ", ".join(args.level) if args.level else "all"))
            scan_fh.flush()                                    # type: ignore
        except OSError as exc:
            print("ERROR: cannot open log-trace: {}".format(exc), file=sys.stderr)
            sys.exit(1)

    # --- open delete log ---
    delete_fh    = None
    delete_path  = ""
    if args.log_delete:
        delete_path = str(Path(args.log_delete).resolve())
        try:
            delete_fh = open_log(args.log_delete)
        except OSError as exc:
            print("ERROR: cannot open log-delete: {}".format(exc), file=sys.stderr)
            if scan_fh:
                scan_fh.close()  # type: ignore
            sys.exit(1)

    try:
        results = scan_and_print(root, level_filter, scan_fh, trace_path)
    finally:
        if scan_fh:
            scan_fh.close()  # type: ignore
            print("\nScan trace log written to: {}".format(_c(trace_path, "cyan")))

    if not results:
        print("\nNo matching files found.")
        if delete_fh:
            delete_fh.close()  # type: ignore
        return

    print()
    try:
        do_delete(results, dry_run=not args.delete,
                  delete_fh=delete_fh, delete_path=delete_path)
    finally:
        if delete_fh:
            delete_fh.close()  # type: ignore
            print("\nDelete log written to: {}".format(_c(delete_path, "cyan")))

    if _interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
