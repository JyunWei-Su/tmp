#!/cld/tools/python3.8.8/bin/python3.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    ic_cleanup.py <scan_root> [options]

Options:
    --out-dir DIR        Write all logs under DIR:
                           DIR/trace.log   -- scan results
                           DIR/delete.log  -- delete actions
                           DIR/error.log   -- filesystem errors (bad inodes etc.)
                         Append .gz to use gzip compression, e.g. --out-dir /tmp/out_gz
                         (files will be trace.log.gz / delete.log.gz / error.log.gz)
    --log-trace FILE     Write scan results to FILE  (overrides --out-dir trace log)
    --log-delete FILE    Write delete actions to FILE (overrides --out-dir delete log)
    --log-error FILE     Write filesystem errors to FILE (overrides --out-dir error log)
    --gz                 When using --out-dir, compress all three logs with gzip
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
import io
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
SAFE        = "Safe"
CAUTION     = "Caution"
DANGER      = "Danger"
PROTECTED   = "Protected"
NOT_CURRENT = "Not-Current"

ALL_LEVELS = (SAFE, CAUTION, DANGER, PROTECTED, NOT_CURRENT)

_NCUR_SAFE = "__NCUR_SAFE__"
_NCUR_KEEP = "__NCUR_KEEP__"

_PLAIN = {
    SAFE:        "[SAFE    ]  ",
    CAUTION:     "[CAUTION ]  ",
    DANGER:      "[DANGER  ]  ",
    PROTECTED:   "[PROTECT ]  ",
    NOT_CURRENT: "[KEEP(CURR)]",
    _NCUR_SAFE:  "[SAFE(NCUR)]",
    _NCUR_KEEP:  "[KEEP(CURR)]",
}

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
#  Rule table
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

    # --- Caution ---
    {"pattern": r".*\.ddc$",                "type": "f",  "level": CAUTION,   "desc": "synthesis snapshot"},
    {"pattern": r".*\.saif$",               "type": "f",  "level": CAUTION,   "desc": "power activity file"},
    {"pattern": r".*\.bit$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.bin$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.mcs$",                "type": "f",  "level": CAUTION,   "desc": "FPGA bitstream"},
    {"pattern": r".*\.pat$",                "type": "f",  "level": CAUTION,   "desc": "DFT pattern"},
    {"pattern": r"^PC_output",              "type": "d",  "level": CAUTION,   "desc": "P&R intermediate layout"},
    {"pattern": r".*\.spef$",               "type": "f",  "level": CAUTION,   "desc": "P&R parasitics"},
    {"pattern": r"^lint_cpdb$",             "type": "d",  "level": CAUTION,   "desc": "VCSG_lint cpdb"},

    # --- Danger ---
    {"pattern": r".*\.v$",                  "type": "f",  "level": DANGER,    "desc": "netlist/RTL (manual confirm)"},
    {"pattern": r".*\.vg$",                 "type": "f",  "level": DANGER,    "desc": "gate-level netlist"},
    {"pattern": r"^report_qor\.rpt$",       "type": "f",  "level": DANGER,    "desc": "STA signoff report"},
    {"pattern": r"^summary_.*\.rpt$",       "type": "f",  "level": DANGER,    "desc": "STA signoff summary"},
    {"pattern": r".*_final\.gds$",          "type": "f",  "level": DANGER,    "desc": "P&R final GDS"},
    {"pattern": r"^ptpx_final",             "type": "fd", "level": DANGER,    "desc": "power signoff"},

    # --- Not-Current ---
    {
        "pattern":  r"^\d{6}.*$",
        "type":     "d",
        "level":    NOT_CURRENT,
        "ancestor": r".*MACRO.*",
        "desc":     "MACRO versioned snapshot",
    },

    # --- Protected ---
    {"pattern": r".*\.sv$",                 "type": "f",  "level": PROTECTED, "desc": "RTL source"},
    {"pattern": r".*\.sdc$",                "type": "f",  "level": PROTECTED, "desc": "timing constraints"},
    {"pattern": r"^Makefile$",              "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.prj$",                "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.sgdc$",               "type": "f",  "level": PROTECTED, "desc": "project config"},
    {"pattern": r".*\.tcl$",                "type": "f",  "level": PROTECTED, "desc": "flow script"},
    {"pattern": r".*\.py$",                 "type": "f",  "level": PROTECTED, "desc": "flow script"},
    {"pattern": r".*\.pl$",                 "type": "f",  "level": PROTECTED, "desc": "flow script"},
]  # type: List[Dict]

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
#  "current" symlink resolution
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
    except (PermissionError, OSError):
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
#  File owner  -- graceful on broken inodes
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
    """Full recursive size via stack-based scandir.
    Checks _interrupted at every Python iteration so Ctrl-C is responsive.
    Returns -1 if interrupted before completion."""
    total  = 0
    stack  = [str(path)]
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


_TAG_COL_W   = len(list(_PLAIN.values())[0])
_OWNER_WIDTH = 12

HEADER_PLAIN = "{:>12}  {:<16}  {:<{tw}}  {:<{ow}}  {:<4}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "OWNER", "TYPE", "PATH",
    tw=_TAG_COL_W, ow=_OWNER_WIDTH,
)
SEP = "-" * 120


def fmt_row(size, mtime, internal, owner, ftype, abs_path, for_file=False):
    # type: (int, float, str, str, str, str, bool) -> str
    tag       = _tag_plain(internal) if for_file else _tag_color(internal)
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
#  Progress line on stderr
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
# ===========================================================================
def open_log(path):
    # type: (str) -> object
    """Open a log file for line-by-line UTF-8 text writing.
    .gz suffix -> gzip with mtime=0 (vim-compatible single-stream gzip)."""
    if path.endswith(".gz"):
        raw = open(path, "wb")
        gz  = gzip.GzipFile(filename="", mode="wb", compresslevel=6,
                             fileobj=raw, mtime=0)
        return io.TextIOWrapper(gz, encoding="utf-8")
    return open(path, "w", encoding="utf-8")


def _write_fh(fh, line):
    # type: (object, str) -> None
    """Write one line and flush immediately (keeps on-disk content current)."""
    if fh is not None:
        fh.write(line + "\n")   # type: ignore[union-attr]
        fh.flush()              # type: ignore[union-attr]


def emit_row(line_term, line_plain, scan_fh, cur_dir):
    # type: (str, str, object, str) -> None
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
#  Error logging helper
# ===========================================================================
def _log_error(error_fh, path, exc):
    # type: (object, str, Exception) -> None
    """Record a filesystem error to error log and stderr (dim)."""
    msg = "ERROR  {}  {}".format(path, exc)
    _clear_progress()
    sys.stderr.write(_c("  " + msg + "\n", "dim"))
    sys.stderr.flush()
    _write_fh(error_fh, msg)


# ===========================================================================
#  Streaming scan
# ===========================================================================
def scan_and_print(root, level_filter, scan_fh, error_fh, trace_path, error_path):
    # type: (Path, Optional[Set[str]], object, object, str, str) -> List[Tuple]
    """
    Result tuples: (size, mtime, effective_level, internal, owner, ftype, abs_path)
    """
    root_real = Path(os.path.realpath(str(root)))

    _clear_progress()
    print(_c(HEADER_PLAIN, "bold"))
    print(SEP)
    _write_fh(scan_fh, HEADER_PLAIN)
    _write_fh(scan_fh, SEP)

    # Always show log path status below header
    print(_c("  log-trace : {}".format(trace_path if trace_path else "(none)"), "dim"))
    print(_c("  log-error : {}".format(error_path if error_path else "(none)"), "dim"))
    print()

    results = []   # type: List[Tuple]
    counts  = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]
    cur_dir = ""

    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False,
                                                onerror=lambda e: None):
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

            # safe is_symlink -- broken inodes return False, never raise
            try:
                is_sym = full.is_symlink()
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                dirnames.remove(dname)
                continue
            if is_sym:
                continue

            result = classify(dname, dp, is_dir=True)
            if result is None:
                continue

            internal, _desc = result
            effective = _effective_level(internal)

            dirnames.remove(dname)

            if level_filter and effective not in level_filter:
                continue

            if _interrupted:
                break

            # stat the entry -- catch all OSError variants (EIO, ESTALE, etc.)
            try:
                st = full.stat()
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                continue

            size = dir_total_size(full)
            if size == -1:
                break

            try:
                mt    = st.st_mtime
                owner = get_owner(full)
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                mt    = 0.0
                owner = "?"

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

            try:
                is_sym = full.is_symlink()
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                continue
            if is_sym:
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
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
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
def do_delete(results, dry_run, delete_fh, error_fh, delete_path):
    # type: (List[Tuple], bool, object, object, str) -> None
    deletable = [r for r in results if r[2] in _DELETABLE]

    if not deletable:
        msg = "\nNothing to delete. (Danger / Protected / Keep are never auto-deleted.)"
        print(msg)
        _write_fh(delete_fh, msg)
        return

    mode      = "DRY-RUN" if dry_run else "DELETE"
    ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag_term  = _c("[{}]".format(mode), "yellow" if dry_run else "red", "bold")
    tag_plain = "[{}]".format(mode)

    print("\n{}  {} items eligible (Safe + Caution only):".format(
        tag_term, len(deletable)))
    print(_c("  log-delete: {}".format(delete_path if delete_path else "(none)"), "dim"))
    print()

    _write_fh(delete_fh, "# IC Cleanup -- delete log")
    _write_fh(delete_fh, "# Date : {}".format(ts))
    _write_fh(delete_fh, "# Mode : {}".format(mode))
    _write_fh(delete_fh, "\n{} {} items eligible (Safe + Caution only):".format(
        tag_plain, len(deletable)))
    _write_fh(delete_fh, SEP)
    _write_fh(delete_fh, HEADER_PLAIN)
    _write_fh(delete_fh, SEP)

    for _size, _mt, effective, internal, owner, ftype, path in deletable:
        if _interrupted:
            msg = "  [INTERRUPTED] delete aborted."
            print(_c(msg, "yellow"))
            _write_fh(delete_fh, msg)
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
                _log_error(error_fh, str(path), exc)  # type: ignore[arg-type]

        print("  {}  {}".format(tag_term, row_term))
        if status != "OK":
            print(_c("             {}".format(status), "red"))
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

    # output directory (convenient single flag)
    p.add_argument("--out-dir", metavar="DIR", default=None,
        dest="out_dir",
        help="Write trace/delete/error logs under DIR "
             "(use --gz to compress)")
    p.add_argument("--gz", action="store_true", default=False,
        help="Compress logs produced by --out-dir with gzip (.gz)")

    # individual overrides
    p.add_argument("--log-trace", metavar="FILE", default=None,
        dest="log_trace",
        help="Scan trace log (overrides --out-dir; .gz = gzip)")
    p.add_argument("--log-delete", metavar="FILE", default=None,
        dest="log_delete",
        help="Delete action log (overrides --out-dir; .gz = gzip)")
    p.add_argument("--log-error", metavar="FILE", default=None,
        dest="log_error",
        help="Filesystem error log (overrides --out-dir; .gz = gzip)")

    p.add_argument("--delete", action="store_true", default=False,
        help="Actually delete Safe/Caution items (default: dry-run)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output: safe caution danger protected not_current")
    return p


def _resolve_log_paths(args):
    # type: (argparse.Namespace) -> Tuple[str, str, str]
    """Return (trace_path, delete_path, error_path) as absolute strings.
    Individual --log-* flags override --out-dir."""
    ext = ".gz" if args.gz else ""

    def _from_dir(name):
        # type: (str) -> str
        if args.out_dir:
            return str(Path(args.out_dir).resolve() / (name + ".log" + ext))
        return ""

    trace_path  = (str(Path(args.log_trace).resolve())
                   if args.log_trace else _from_dir("trace"))
    delete_path = (str(Path(args.log_delete).resolve())
                   if args.log_delete else _from_dir("delete"))
    error_path  = (str(Path(args.log_error).resolve())
                   if args.log_error else _from_dir("error"))
    return trace_path, delete_path, error_path


def _open_log_safe(path, label):
    # type: (str, str) -> Optional[object]
    """Open a log file; print error and return None on failure."""
    if not path:
        return None
    try:
        return open_log(path)
    except OSError as exc:
        print("ERROR: cannot open {}: {}".format(label, exc), file=sys.stderr)
        return None


def main():
    # type: () -> None
    _install_sigint_handler()

    args = build_parser().parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print("ERROR: directory not found: {}".format(root), file=sys.stderr)
        sys.exit(1)

    # Create --out-dir if needed
    if args.out_dir:
        try:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print("ERROR: cannot create out-dir: {}".format(exc), file=sys.stderr)
            sys.exit(1)

    level_filter = None  # type: Optional[Set[str]]
    if args.level:
        level_filter = {LEVEL_MAP[l] for l in args.level}

    root_real = Path(os.path.realpath(str(root)))
    print("Scanning: {}\n".format(_c(str(root_real), "bold")))

    trace_path, delete_path, error_path = _resolve_log_paths(args)

    # Open all three logs (None if not configured)
    scan_fh  = _open_log_safe(trace_path,  "--log-trace")
    error_fh = _open_log_safe(error_path,  "--log-error")
    delete_fh = _open_log_safe(delete_path, "--log-delete")

    if scan_fh:
        _write_fh(scan_fh, "# IC Cleanup -- scan trace log")
        _write_fh(scan_fh, "# Root  : {}".format(root_real))
        _write_fh(scan_fh, "# Date  : {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        _write_fh(scan_fh, "# Filter: {}\n".format(
            ", ".join(args.level) if args.level else "all"))

    if error_fh:
        _write_fh(error_fh, "# IC Cleanup -- filesystem error log")
        _write_fh(error_fh, "# Root  : {}".format(root_real))
        _write_fh(error_fh, "# Date  : {}\n".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    try:
        results = scan_and_print(root, level_filter,
                                 scan_fh, error_fh,
                                 trace_path, error_path)
    finally:
        if scan_fh:
            scan_fh.close()   # type: ignore
            print("\nScan trace log  : {}".format(_c(trace_path, "cyan")))
        if error_fh:
            error_fh.close()  # type: ignore
            print("Filesystem errors: {}".format(_c(error_path, "cyan")))

    if not results:
        print("\nNo matching files found.")
        if delete_fh:
            delete_fh.close()  # type: ignore
        return

    print()
    try:
        do_delete(results, dry_run=not args.delete,
                  delete_fh=delete_fh, error_fh=error_fh,
                  delete_path=delete_path)
    finally:
        if delete_fh:
            delete_fh.close()  # type: ignore
            print("\nDelete log      : {}".format(_c(delete_path, "cyan")))

    if _interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
