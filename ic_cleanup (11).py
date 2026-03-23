#!/cld/tools/python3.8.8/bin/python3.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    ic_cleanup.py <scan_root> [options]

Options:
    --rules FILE     JSON rule file (default: rules.json beside this script)
    --out-dir DIR    Write all logs under DIR:
                       trace.log   -- scan results with rule IDs
                       delete.log  -- delete / gzip actions
                       error.log   -- filesystem errors
                       rule.log    -- loaded rule table
                       summary.log -- per-rule hit counts + action statistics
                       svndir.log  -- SVN working copy dirs found (not scanned inside)
    --gz             Compress all --out-dir logs with gzip (.log.gz)
    --delete         Actually perform actions (delete / gzip); default: dry-run

Levels:
    safe        -- delete the file/dir
    gzip        -- gzip file (*.gz same dir); dir -> tar.gz at parent, remove original
                   if .gz/.tar.gz already exists: skip
    protected   -- never touched
    not_current -- sibling of a 'current*' symlink target: KEEP(CURR) / protected
                   all others: SAFE(NCUR) / deleted like safe

JSON rule fields:
    pattern  (required) : Python regex against basename
    type     (required) : f | d | fd
    level    (required) : safe | gzip | protected | not_current
    ancestor (optional) : Python regex against any ancestor dir name
    desc     (optional) : label
"""

import argparse
import gzip as _gzip_mod
import io
import json
import os
import pwd
import re
import shutil
import signal
import sys
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ===========================================================================
#  ANSI color helpers
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
    "magenta":"\033[35m",
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
SAFE        = "Safe"        # delete
GZIP        = "Gzip"        # compress, delete original
PROTECTED   = "Protected"   # never touch
NOT_CURRENT = "Not-Current" # depends on current symlink

ALL_LEVELS = (SAFE, GZIP, PROTECTED, NOT_CURRENT)

# Internal sentinels for not_current outcomes
_NCUR_SAFE = "__NCUR_SAFE__"   # deletable (like SAFE)
_NCUR_KEEP = "__NCUR_KEEP__"   # protected (like PROTECTED)

# ---------------------------------------------------------------------------
#  Tags -- all padded to the same width
#  Longest: "[SAFE(NCUR)]" = 12 chars
# ---------------------------------------------------------------------------
_PLAIN = {
    SAFE:        "[SAFE    ]  ",   # 12
    GZIP:        "[GZIP    ]  ",   # 12
    PROTECTED:   "[PROTECT ]  ",   # 12
    NOT_CURRENT: "[KEEP(CURR)]",   # 12
    _NCUR_SAFE:  "[SAFE(NCUR)]",   # 12
    _NCUR_KEEP:  "[KEEP(CURR)]",   # 12
}

_tl = set(len(v) for v in _PLAIN.values())
assert len(_tl) == 1, "Tag width mismatch: {}".format(
    {k: len(v) for k, v in _PLAIN.items()})

_COLOR = {
    SAFE:        _c(_PLAIN[SAFE],        "green",   "bold"),
    GZIP:        _c(_PLAIN[GZIP],        "magenta", "bold"),
    PROTECTED:   _c(_PLAIN[PROTECTED],   "cyan",    "bold"),
    NOT_CURRENT: _c(_PLAIN[NOT_CURRENT], "blue",    "bold"),
    _NCUR_SAFE:  _c(_PLAIN[_NCUR_SAFE],  "green",   "bold"),
    _NCUR_KEEP:  _c(_PLAIN[_NCUR_KEEP],  "blue",    "bold"),
}

# Implicit rule ID for SVN working copy detection (not in RULES list)
SVN_RULE_ID   = "SVN"
SVN_LEVEL_STR = "Svn-WC"   # displayed in trace / summary

# SVN tag uses same width as other tags
_PLAIN_SVN = "[SVN-WC  ]  "   # 12 chars
assert len(_PLAIN_SVN) == len(list(_PLAIN.values())[0]), \
    "SVN tag width mismatch"
_COLOR_SVN = _c(_PLAIN_SVN, "yellow", "bold")

# levels that result in an action (delete or gzip)
_ACTIONABLE = (SAFE, GZIP)

# Map JSON level string -> constant
_LEVEL_FROM_JSON = {
    "safe":        SAFE,
    "gzip":        GZIP,
    "protected":   PROTECTED,
    "not_current": NOT_CURRENT,
}

LEVEL_MAP = _LEVEL_FROM_JSON


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
#  Rule loading
# ===========================================================================
RULES = []  # type: List[Dict]


def load_rules(json_path):
    # type: (str) -> List[Dict]
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        print("ERROR: cannot load rules from {}: {}".format(json_path, exc),
              file=sys.stderr)
        sys.exit(1)

    raw = data.get("rules")
    if not isinstance(raw, list) or not raw:
        print("ERROR: rules.json must have a non-empty 'rules' list",
              file=sys.stderr)
        sys.exit(1)

    loaded = []  # type: List[Dict]
    rule_num = 0
    for entry in raw:
        if "pattern" not in entry:   # skip _group / _comment entries
            continue
        rule_num += 1
        rule_id  = "R{:03d}".format(rule_num)
        pattern  = entry.get("pattern", "")
        rtype    = entry.get("type",    "fd")
        level_s  = entry.get("level",  "safe").lower().replace("-", "_")
        ancestor = entry.get("ancestor", None)
        desc     = entry.get("desc", "")

        if level_s not in _LEVEL_FROM_JSON:
            print("ERROR: rule {} unknown level '{}' (valid: {})".format(
                rule_id, level_s, list(_LEVEL_FROM_JSON.keys())), file=sys.stderr)
            sys.exit(1)

        try:
            pat_re = re.compile(pattern)
        except re.error as exc:
            print("ERROR: rule {} pattern '{}': {}".format(
                rule_id, pattern, exc), file=sys.stderr)
            sys.exit(1)

        anc_re = None
        if ancestor:
            try:
                anc_re = re.compile(ancestor)
            except re.error as exc:
                print("ERROR: rule {} ancestor '{}': {}".format(
                    rule_id, ancestor, exc), file=sys.stderr)
                sys.exit(1)

        loaded.append({
            "id":           rule_id,
            "pattern":      pattern,
            "type":         rtype,
            "level":        _LEVEL_FROM_JSON[level_s],
            "ancestor":     ancestor or "",
            "desc":         desc,
            "_pat_re":      pat_re,
            "_ancestor_re": anc_re,
        })

    return loaded


def write_rule_log(rules, fh):
    # type: (List[Dict], object) -> None
    if fh is None:
        return
    _write_fh(fh, "# IC Cleanup -- rule table")
    _write_fh(fh, "# Generated : {}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    _write_fh(fh, "# Total     : {}".format(len(rules)))
    _write_fh(fh, "")
    hdr = "{:<6}  {:<12}  {:<4}  {:<24}  {:<32}  {}".format(
        "ID", "LEVEL", "TYPE", "ANCESTOR", "DESC", "PATTERN")
    sep = "-" * 110
    _write_fh(fh, hdr)
    _write_fh(fh, sep)
    for r in rules:
        _write_fh(fh, "{:<6}  {:<12}  {:<4}  {:<24}  {:<32}  {}".format(
            r["id"], r["level"], r["type"],
            r["ancestor"] or "(any)", r["desc"], r["pattern"]))
    _write_fh(fh, sep)


# ===========================================================================
#  Ancestor check
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
#  Classification  ->  (internal, desc, rule_id)  or  None
# ===========================================================================
def classify(name, parent, is_dir):
    # type: (str, Path, bool) -> Optional[Tuple[str, str, str]]
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

        level   = rule["level"]
        desc    = rule.get("desc", "")
        rule_id = rule["id"]

        if level == NOT_CURRENT:
            if name in get_current_targets(parent):
                return _NCUR_KEEP, desc, rule_id
            return _NCUR_SAFE, desc, rule_id

        return level, desc, rule_id

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
_RULE_WIDTH  = 6

HEADER_PLAIN = "{:>12}  {:<16}  {:<{tw}}  {:<{ow}}  {:<4}  {:<{rw}}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "OWNER", "TYPE", "RULE", "PATH",
    tw=_TAG_COL_W, ow=_OWNER_WIDTH, rw=_RULE_WIDTH,
)
SEP = "-" * 130


def fmt_row(size, mtime, internal, owner, ftype, rule_id, abs_path, for_file=False):
    # type: (int, float, str, str, str, str, str, bool) -> str
    tag       = _tag_plain(internal) if for_file else _tag_color(internal)
    ftype_str = "DIR " if ftype == "D" else "FILE"
    return "{:>12}  {:<16}  {}  {:<{ow}}  {:<4}  {:<{rw}}  {}".format(
        human_size(size), fmt_mtime(mtime), tag,
        owner, ftype_str, rule_id, abs_path,
        ow=_OWNER_WIDTH, rw=_RULE_WIDTH,
    )


# ===========================================================================
#  Progress line
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
    if path.endswith(".gz"):
        raw = open(path, "wb")
        gz  = _gzip_mod.GzipFile(filename="", mode="wb", compresslevel=6,
                                  fileobj=raw, mtime=0)
        return io.TextIOWrapper(gz, encoding="utf-8")
    return open(path, "w", encoding="utf-8")


def _write_fh(fh, line):
    # type: (object, str) -> None
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
        _c("\n[INTERRUPTED] Ctrl-C caught -- stopping scan...\n", "yellow", "bold"))
    sys.stderr.flush()


def _install_sigint_handler():
    signal.signal(signal.SIGINT, _handle_sigint)


# ===========================================================================
#  Error logging
# ===========================================================================
def _log_error(error_fh, path, exc):
    # type: (object, str, Exception) -> None
    msg = "ERROR  {}  {}".format(path, exc)
    _clear_progress()
    sys.stderr.write(_c("  " + msg + "\n", "dim"))
    sys.stderr.flush()
    _write_fh(error_fh, msg)


# ===========================================================================
#  Statistics tracker
#  Tracks per-rule hit counts and per-action (delete/gzip) counts + sizes.
# ===========================================================================
class Stats(object):
    def __init__(self, rules):
        # type: (List[Dict]) -> None
        # rule_id -> {hits, size}
        self.rule_hits = {r["id"]: {"hits": 0, "size": 0} for r in rules}
        # SVN working copy hits (implicit rule)
        self.svn_count = 0
        self.svn_size  = 0
        # action counts (populated during do_actions)
        self.deleted_count  = 0
        self.deleted_size   = 0
        self.gzipped_count  = 0
        self.gzipped_size   = 0
        self.skipped_count  = 0   # gz already exists
        self.error_count    = 0

    def record_scan(self, rule_id, size):
        # type: (str, int) -> None
        if rule_id in self.rule_hits:
            self.rule_hits[rule_id]["hits"] += 1
            self.rule_hits[rule_id]["size"] += max(size, 0)

    def record_svn(self, size):
        # type: (int) -> None
        self.svn_count += 1
        self.svn_size  += max(size, 0)


# ===========================================================================
#  SVN working copy detection
# ===========================================================================
SVN_HEADER_PLAIN = "{:>12}  {:<16}  {:<12}  {:<12}  {}".format(
    "SIZE", "MODIFIED", "LEVEL", "OWNER", "PATH")
SVN_SEP = "-" * 100


def is_svn_wc(dirpath):
    # type: (Path) -> bool
    """Return True if dirpath contains a .svn subdirectory (any depth = 1)."""
    try:
        return (dirpath / ".svn").is_dir()
    except OSError:
        return False


def emit_svn_row(size, mtime, owner, abs_path, svn_fh, scan_fh, cur_dir):
    # type: (int, float, str, str, object, object, str) -> None
    """Emit one SVN-WC row to terminal, trace log, and svn log."""
    plain = "{:>12}  {:<16}  {:<12}  {:<12}  {}".format(
        human_size(size), fmt_mtime(mtime), SVN_LEVEL_STR, owner, abs_path)
    colored = "{:>12}  {:<16}  {}  {:<12}  {}".format(
        human_size(size), fmt_mtime(mtime),
        _COLOR_SVN, owner, abs_path)

    _clear_progress()
    print(colored)
    _write_fh(scan_fh, _PLAIN_SVN.rstrip() + "  " + plain)   # trace log
    _write_fh(svn_fh,  plain)                                  # svn log
    if cur_dir:
        _progress(cur_dir)
def scan_and_print(root, level_filter, scan_fh, error_fh, svn_fh,
                   trace_path, error_path, svn_path, stats):
    # type: (Path, Optional[Set[str]], object, object, object, str, str, str, Stats) -> List[Tuple]
    """
    Result tuples:
      (size, mtime, effective_level, internal, owner, ftype, rule_id, abs_path)
    SVN working copy dirs are recorded separately and NOT included in results.
    """
    root_real = Path(os.path.realpath(str(root)))

    _clear_progress()
    print(_c(HEADER_PLAIN, "bold"))
    print(SEP)
    _write_fh(scan_fh, HEADER_PLAIN)
    _write_fh(scan_fh, SEP)

    print(_c("  log-trace : {}".format(trace_path if trace_path else "(none)"), "dim"))
    print(_c("  log-error : {}".format(error_path if error_path else "(none)"), "dim"))
    print(_c("  log-svndir: {}".format(svn_path   if svn_path   else "(none)"), "dim"))
    print()

    results = []   # type: List[Tuple]
    counts  = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]
    cur_dir = ""

    for dirpath, dirnames, filenames in os.walk(
            str(root), followlinks=False, onerror=lambda e: None):
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
            try:
                if full.is_symlink():
                    continue
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                dirnames.remove(dname)
                continue

            # --- SVN working copy detection (implicit rule, highest priority) ---
            if is_svn_wc(full):
                dirnames.remove(dname)   # do not descend
                try:
                    st    = full.stat()
                    size  = dir_total_size(full)
                    if size == -1:
                        break
                    mt    = st.st_mtime
                    owner = get_owner(full)
                except OSError as exc:
                    _log_error(error_fh, str(full), exc)
                    continue
                abs_path = str(root_real / full.relative_to(root))
                emit_svn_row(size, mt, owner, abs_path, svn_fh, scan_fh, cur_dir)
                stats.record_svn(size)
                continue

            result = classify(dname, dp, is_dir=True)
            if result is None:
                continue
            internal, _desc, rule_id = result
            effective = _effective_level(internal)
            dirnames.remove(dname)

            if level_filter and effective not in level_filter:
                continue
            if _interrupted:
                break

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
                mt, owner = 0.0, "?"

            abs_path = str(root_real / full.relative_to(root))
            emit_row(
                fmt_row(size, mt, internal, owner, "D", rule_id, abs_path, for_file=False),
                fmt_row(size, mt, internal, owner, "D", rule_id, abs_path, for_file=True),
                scan_fh, cur_dir,
            )
            results.append((size, mt, effective, internal, owner, "D", rule_id, Path(abs_path)))
            counts[effective] += 1
            stats.record_scan(rule_id, size)

        # --- files ---
        for fname in filenames:
            if _interrupted:
                break
            full = dp / fname
            try:
                if full.is_symlink():
                    continue
            except OSError as exc:
                _log_error(error_fh, str(full), exc)
                continue

            result = classify(fname, dp, is_dir=False)
            if result is None:
                continue
            internal, _desc, rule_id = result
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
                fmt_row(size, mt, internal, owner, "F", rule_id, abs_path, for_file=False),
                fmt_row(size, mt, internal, owner, "F", rule_id, abs_path, for_file=True),
                scan_fh, cur_dir,
            )
            results.append((size, mt, effective, internal, owner, "F", rule_id, Path(abs_path)))
            counts[effective] += 1
            stats.record_scan(rule_id, size)

    _clear_progress()

    total_size  = sum(r[0] for r in results)
    total_count = len(results)
    partial     = "  [PARTIAL - scan interrupted]" if _interrupted else ""

    summary = (
        "Total {} items  |  "
        "Safe: {}  Gzip: {}  Protected: {}  Keep: {}  SVN-WC: {}  |  "
        "Est. size: {}{}"
    ).format(
        total_count,
        counts[SAFE], counts[GZIP], counts[PROTECTED], counts[NOT_CURRENT],
        stats.svn_count,
        human_size(total_size), partial,
    )

    print(SEP)
    print(_c(summary, "bold"))
    _write_fh(scan_fh, SEP)
    _write_fh(scan_fh, summary)

    return results


# ===========================================================================
#  Gzip action helpers
# ===========================================================================
def _gzip_file(src_path, error_fh):
    # type: (Path, object) -> Tuple[str, int]
    """Gzip a single file in-place.  Returns (status, bytes_saved).
    status: 'OK' | 'SKIP' | 'ERROR: ...'"""
    gz_path = Path(str(src_path) + ".gz")
    if gz_path.exists():
        return "SKIP", 0
    try:
        orig_size = src_path.stat().st_size
        with open(str(src_path), "rb") as f_in:
            raw = open(str(gz_path), "wb")
            gz  = _gzip_mod.GzipFile(filename="", mode="wb",
                                     compresslevel=6, fileobj=raw, mtime=0)
            shutil.copyfileobj(f_in, gz)
            gz.close()
            raw.close()
        src_path.unlink()
        return "OK", orig_size
    except Exception as exc:
        _log_error(error_fh, str(src_path), exc)
        return "ERROR: {}".format(exc), 0


def _gzip_dir(src_path, error_fh):
    # type: (Path, object) -> Tuple[str, int]
    """Tar+gzip a directory.  tar.gz placed at parent.  Original removed.
    Returns (status, bytes_saved)."""
    tar_path = src_path.parent / (src_path.name + ".tar.gz")
    if tar_path.exists():
        return "SKIP", 0
    try:
        orig_size = dir_total_size(src_path)
        if orig_size == -1:
            return "INTERRUPTED", 0
        with tarfile.open(str(tar_path), "w:gz") as tf:
            tf.add(str(src_path), arcname=src_path.name)
        shutil.rmtree(str(src_path))
        return "OK", orig_size
    except Exception as exc:
        _log_error(error_fh, str(src_path), exc)
        return "ERROR: {}".format(exc), 0


# ===========================================================================
#  Actions (delete / gzip)
# ===========================================================================
def do_actions(results, dry_run, delete_fh, error_fh, delete_path, stats):
    # type: (List[Tuple], bool, object, object, str, Stats) -> None
    actionable = [r for r in results if r[2] in _ACTIONABLE]

    if not actionable:
        msg = "\nNothing to act on. (Protected / Keep are never touched.)"
        print(msg)
        _write_fh(delete_fh, msg)
        return

    mode      = "DRY-RUN" if dry_run else "EXECUTE"
    ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag_term  = _c("[{}]".format(mode), "yellow" if dry_run else "red", "bold")
    tag_plain = "[{}]".format(mode)

    print("\n{}  {} items to act on (Safe=delete, Gzip=compress):".format(
        tag_term, len(actionable)))
    print(_c("  log-delete: {}".format(delete_path if delete_path else "(none)"), "dim"))
    print()

    _write_fh(delete_fh, "# IC Cleanup -- action log")
    _write_fh(delete_fh, "# Date : {}".format(ts))
    _write_fh(delete_fh, "# Mode : {}".format(mode))
    _write_fh(delete_fh, SEP)
    _write_fh(delete_fh, HEADER_PLAIN + "  ACTION  STATUS")
    _write_fh(delete_fh, SEP)

    for _size, _mt, effective, internal, owner, ftype, rule_id, path in actionable:
        if _interrupted:
            msg = "  [INTERRUPTED] actions aborted."
            print(_c(msg, "yellow"))
            _write_fh(delete_fh, msg)
            break

        row_plain = fmt_row(_size, _mt, internal, owner, ftype, rule_id,
                            str(path), for_file=True)
        row_term  = fmt_row(_size, _mt, internal, owner, ftype, rule_id,
                            str(path), for_file=False)

        action = "GZIP" if effective == GZIP else "DELETE"
        status = "DRY-RUN"

        if not dry_run:
            if effective == GZIP:
                if ftype == "D":
                    status, saved = _gzip_dir(path, error_fh)
                else:
                    status, saved = _gzip_file(path, error_fh)
                if status == "OK":
                    stats.gzipped_count += 1
                    stats.gzipped_size  += saved
                elif status == "SKIP":
                    stats.skipped_count += 1
                else:
                    stats.error_count   += 1
            else:
                try:
                    if path.is_dir():
                        shutil.rmtree(str(path))
                    else:
                        path.unlink()
                    status = "OK"
                    stats.deleted_count += 1
                    stats.deleted_size  += max(_size, 0)
                except Exception as exc:
                    status = "ERROR: {}".format(exc)
                    stats.error_count   += 1
                    _log_error(error_fh, str(path), exc)  # type: ignore[arg-type]

        status_color = status
        if status == "OK":
            status_color = _c("OK", "green")
        elif status == "SKIP":
            status_color = _c("SKIP (.gz exists)", "yellow")
        elif status == "DRY-RUN":
            status_color = _c("DRY-RUN", "dim")
        elif status.startswith("ERROR"):
            status_color = _c(status, "red")

        print("  {}  {}  {}  {}".format(tag_term, row_term, action, status_color))
        _write_fh(delete_fh, "{}  {}  {}".format(row_plain, action, status))

    _write_fh(delete_fh, SEP)
    if dry_run and not _interrupted:
        hint = "  (Add --delete to actually perform actions.)"
        print("\n" + hint)
        _write_fh(delete_fh, hint)


# ===========================================================================
#  Summary log
# ===========================================================================
def write_summary(rules, stats, dry_run, root_real, out_path):
    # type: (List[Dict], Stats, bool, Path, str) -> None
    if not out_path:
        return

    mode = "DRY-RUN" if dry_run else "EXECUTED"
    lines = [
        "# IC Cleanup -- summary log",
        "# Date  : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "# Root  : {}".format(root_real),
        "# Mode  : {}".format(mode),
        "",
        "=== Rule Hit Count ===",
        "{:<6}  {:<12}  {:<32}  {:>8}  {:>12}".format(
            "ID", "LEVEL", "DESC", "HITS", "EST.SIZE"),
        "-" * 80,
    ]

    # only show rules that were hit
    any_hit = False
    for r in rules:
        info = stats.rule_hits.get(r["id"], {"hits": 0, "size": 0})
        if info["hits"] == 0:
            continue
        any_hit = True
        lines.append("{:<6}  {:<12}  {:<32}  {:>8}  {:>12}".format(
            r["id"], r["level"], r["desc"][:32],
            info["hits"], human_size(info["size"])))

    if not any_hit:
        lines.append("  (no rules matched)")
    lines.append("-" * 80)

    total_hits = sum(v["hits"] for v in stats.rule_hits.values())
    total_size = sum(v["size"] for v in stats.rule_hits.values())
    lines.append("{:<6}  {:<12}  {:<32}  {:>8}  {:>12}".format(
        "TOTAL", "", "", total_hits, human_size(total_size)))

    lines += [
        "",
        "=== SVN Working Copy ===",
        "  Detected : {:>6} dirs    {}  (not scanned inside)".format(
            stats.svn_count, human_size(stats.svn_size)),
        "",
        "=== Action Summary ===",
    ]

    if dry_run:
        lines.append("  (dry-run -- no actions performed)")
    else:
        lines += [
            "  Deleted  : {:>6} items   {}".format(
                stats.deleted_count, human_size(stats.deleted_size)),
            "  Gzipped  : {:>6} items   {}".format(
                stats.gzipped_count, human_size(stats.gzipped_size)),
            "  Skipped  : {:>6} items   (gz already existed)".format(
                stats.skipped_count),
            "  Errors   : {:>6}".format(stats.error_count),
        ]

    try:
        fh = open_log(out_path)
        for line in lines:
            _write_fh(fh, line)
        fh.close()  # type: ignore
    except OSError as exc:
        print("ERROR: cannot write summary log {}: {}".format(out_path, exc),
              file=sys.stderr)


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
    p.add_argument("root", help="Root directory to scan")
    p.add_argument("--rules", metavar="FILE", default=None,
        dest="rules_file",
        help="JSON rule file (default: rules.json beside this script)")
    p.add_argument("--out-dir", metavar="DIR", default=None,
        dest="out_dir",
        help="Write all logs (trace/delete/error/rule/summary) under DIR")
    p.add_argument("--gz", action="store_true", default=False,
        help="Compress all --out-dir logs with gzip (.log.gz)")
    p.add_argument("--delete", action="store_true", default=False,
        help="Actually perform delete/gzip actions (default: dry-run)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output: safe gzip protected not_current")
    return p


def _log_paths(out_dir, gz):
    # type: (str, bool) -> Tuple[str, str, str, str, str, str]
    """Return (trace, delete, error, rule, summary, svndir) paths under out_dir."""
    ext = ".gz" if gz else ""
    base = Path(out_dir).resolve()

    def p(name):
        # type: (str) -> str
        return str(base / (name + ".log" + ext))

    return p("trace"), p("delete"), p("error"), p("rule"), p("summary"), p("svndir")


def _open_log_safe(path, label):
    # type: (str, str) -> Optional[object]
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

    # --- rules ---
    rules_path = args.rules_file or str(
        Path(__file__).resolve().parent / "rules.json")
    if not os.path.exists(rules_path):
        print("ERROR: rule file not found: {}".format(rules_path), file=sys.stderr)
        sys.exit(1)

    global RULES
    RULES = load_rules(rules_path)
    print("Loaded {} rules from {}".format(len(RULES), _c(rules_path, "cyan")))

    # --- scan root ---
    root = Path(args.root).resolve()
    if not root.exists():
        print("ERROR: directory not found: {}".format(root), file=sys.stderr)
        sys.exit(1)

    # --- out-dir ---
    if args.out_dir:
        try:
            Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            print("ERROR: cannot create out-dir: {}".format(exc), file=sys.stderr)
            sys.exit(1)
        trace_p, delete_p, error_p, rule_p, summary_p, svn_p = _log_paths(
            args.out_dir, args.gz)
    else:
        trace_p = delete_p = error_p = rule_p = summary_p = svn_p = ""

    level_filter = None  # type: Optional[Set[str]]
    if args.level:
        level_filter = {LEVEL_MAP[l] for l in args.level}

    root_real = Path(os.path.realpath(str(root)))
    print("Scanning: {}\n".format(_c(str(root_real), "bold")))

    # --- stats ---
    stats = Stats(RULES)

    # --- open logs ---
    scan_fh   = _open_log_safe(trace_p,  "trace log")
    error_fh  = _open_log_safe(error_p,  "error log")
    delete_fh = _open_log_safe(delete_p, "delete log")
    rule_fh   = _open_log_safe(rule_p,   "rule log")
    svn_fh    = _open_log_safe(svn_p,    "svndir log")

    write_rule_log(RULES, rule_fh)
    if rule_fh:
        rule_fh.close()  # type: ignore
        print("Rule log   : {}".format(_c(rule_p, "cyan")))

    if scan_fh:
        _write_fh(scan_fh, "# IC Cleanup -- scan trace log")
        _write_fh(scan_fh, "# Root  : {}".format(root_real))
        _write_fh(scan_fh, "# Rules : {}  ({})".format(rules_path, len(RULES)))
        _write_fh(scan_fh, "# Date  : {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        _write_fh(scan_fh, "# Filter: {}\n".format(
            ", ".join(args.level) if args.level else "all"))

    if error_fh:
        _write_fh(error_fh, "# IC Cleanup -- filesystem error log")
        _write_fh(error_fh, "# Root  : {}".format(root_real))
        _write_fh(error_fh, "# Date  : {}\n".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    if svn_fh:
        _write_fh(svn_fh, "# IC Cleanup -- SVN working copy directory log")
        _write_fh(svn_fh, "# Root  : {}".format(root_real))
        _write_fh(svn_fh, "# Date  : {}\n".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        _write_fh(svn_fh, SVN_HEADER_PLAIN)
        _write_fh(svn_fh, SVN_SEP)

    try:
        results = scan_and_print(root, level_filter,
                                 scan_fh, error_fh, svn_fh,
                                 trace_p, error_p, svn_p, stats)
    finally:
        if scan_fh:
            scan_fh.close()  # type: ignore
            print("\nTrace log  : {}".format(_c(trace_p, "cyan")))
        if error_fh:
            error_fh.close()  # type: ignore
            print("Error log  : {}".format(_c(error_p, "cyan")))
        if svn_fh:
            svn_fh.close()  # type: ignore
            print("SVNdir log : {}".format(_c(svn_p, "cyan")))

    if not results:
        print("\nNo matching files found.")
        if delete_fh:
            delete_fh.close()  # type: ignore
        write_summary(RULES, stats, not args.delete, root_real, summary_p)
        if summary_p:
            print("Summary    : {}".format(_c(summary_p, "cyan")))
        return

    print()
    try:
        do_actions(results, dry_run=not args.delete,
                   delete_fh=delete_fh, error_fh=error_fh,
                   delete_path=delete_p, stats=stats)
    finally:
        if delete_fh:
            delete_fh.close()  # type: ignore
            print("\nDelete log : {}".format(_c(delete_p, "cyan")))

    write_summary(RULES, stats, not args.delete, root_real, summary_p)
    if summary_p:
        print("Summary    : {}".format(_c(summary_p, "cyan")))

    if _interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
