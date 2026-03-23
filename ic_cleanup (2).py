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
    current  -- sibling of a 'current*' symlink target: KEEP(CURR) / protected
                   all others: SAFE(NCUR) / deleted like safe

JSON rule fields:
    pattern  (required) : Python regex against basename
    type     (required) : f | d | fd
    level    (required) : safe | gzip | protected | current
    ancestor (optional) : Python regex against any ancestor dir name
    desc     (optional) : label
"""

import argparse
import concurrent.futures as _futures
import gzip as _gzip_mod
import io
import json
import os
import pwd
import queue as _queue
import re
import shutil
import signal
import sys
import tarfile
import threading
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
SAFE      = "Safe"       # delete
GZIP      = "Gzip"       # compress then delete original
PROTECTED = "Protected"  # never touch
CURRENT   = "Current"    # versioned dir: keep if symlink points here, else delete
SVN_WC    = "Svn-WC"     # SVN working copy (implicit, not in RULES)

ALL_LEVELS = (SAFE, GZIP, PROTECTED, CURRENT)

# levels that result in an action (delete or gzip)
_ACTIONABLE = (SAFE, GZIP)

# Map JSON level string -> constant  ("not_current" no longer accepted (use "current"))
_LEVEL_FROM_JSON = {
    "safe":      SAFE,
    "gzip":      GZIP,
    "protected": PROTECTED,
    "current":   CURRENT,
}

LEVEL_MAP = _LEVEL_FROM_JSON   # alias for CLI --level filter

# ---------------------------------------------------------------------------
#  Tags -- ALL exactly _TAG_W characters (padding goes INSIDE the brackets)
#
#  Format:  [<content padded to TAG_W-2 chars>]
#  _TAG_W = 12  =>  content field = 10 chars
#
#  SAFE(NCUR) and KEEP(CURR) are shown for CURRENT-rule entries depending
#  on whether the directory is the symlink target or not.
#  They are stored as separate display-only keys "_ncur_safe" / "_ncur_keep"
#  so classify() can return them directly without sentinel indirection.
# ---------------------------------------------------------------------------
_TAG_W = 12   # total tag width including [ and ]

def _mk_tag(inner):
    # type: (str) -> str
    """Pad inner text to (_TAG_W - 2) chars, wrap in brackets."""
    return "[{:<{w}}]".format(inner, w=_TAG_W - 2)

# Public level tags
_PLAIN = {
    SAFE:         _mk_tag("SAFE      "),   # [SAFE      ]
    GZIP:         _mk_tag("GZIP      "),   # [GZIP      ]
    PROTECTED:    _mk_tag("PROTECT   "),   # [PROTECT   ]
    CURRENT:      _mk_tag("KEEP(CURR)"),   # [KEEP(CURR)]
    # Display variants for CURRENT-rule entries
    "_ncur_safe": _mk_tag("SAFE(NCUR)"),   # [SAFE(NCUR)]  -- deletable
    "_ncur_keep": _mk_tag("KEEP(CURR)"),   # [KEEP(CURR)]  -- protected
    # SVN implicit rule
    SVN_WC:       _mk_tag("SVN-WC    "),   # [SVN-WC    ]
}

# Verify all tags are exactly _TAG_W chars
_bad = {k: len(v) for k, v in _PLAIN.items() if len(v) != _TAG_W}
assert not _bad, "Tag width mismatch (want {}): {}".format(_TAG_W, _bad)

_COLOR = {k: _c(v, *({
    SAFE:         ("green",   "bold"),
    GZIP:         ("magenta", "bold"),
    PROTECTED:    ("cyan",    "bold"),
    CURRENT:      ("blue",    "bold"),
    "_ncur_safe": ("green",   "bold"),
    "_ncur_keep": ("blue",    "bold"),
    SVN_WC:       ("yellow",  "bold"),
}.get(k, ("reset",))))
    for k, v in _PLAIN.items()
}


def _tag_plain(key):
    # type: (str) -> str
    return _PLAIN[key]


def _tag_color(key):
    # type: (str) -> str
    return _COLOR[key]


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
#  Classification  ->  (tag_key, desc, rule_id)  or  None
#
#  tag_key is one of: SAFE, GZIP, PROTECTED, CURRENT,
#                     "_ncur_safe", "_ncur_keep"
#  It is used directly as the key into _PLAIN / _COLOR.
#  For action decisions use _action_level(tag_key).
# ===========================================================================
def _action_level(tag_key):
    # type: (str) -> str
    """Map a tag_key to the level constant used for action decisions."""
    if tag_key == "_ncur_safe":
        return SAFE
    if tag_key == "_ncur_keep":
        return CURRENT
    return tag_key


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

        if level == CURRENT:
            if name in get_current_targets(parent):
                return "_ncur_keep", desc, rule_id   # protected: current symlink target
            return "_ncur_safe", desc, rule_id        # deletable: not the current target

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


SVN_RULE_ID   = "SVN"
SVN_LEVEL_STR = "Svn-WC"

_TAG_COL_W   = _TAG_W    # already defined above as 12
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


# Lock protecting all terminal + log writes (needed when drain thread emits)
_emit_lock = threading.Lock()


def emit_row(line_term, line_plain, scan_fh, cur_dir):
    # type: (str, str, object, str) -> None
    with _emit_lock:
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
SVN_HEADER_PLAIN = HEADER_PLAIN   # reuse the same header
SVN_SEP          = SEP


def is_svn_wc(dirpath):
    # type: (Path) -> bool
    """Return True if dirpath contains a .svn subdirectory."""
    try:
        return (dirpath / ".svn").is_dir()
    except OSError:
        return False


def emit_svn_row(size, mtime, owner, abs_path, svn_fh, scan_fh, cur_dir):
    # type: (int, float, str, str, object, object, str) -> None
    """Emit one SVN-WC row using the same column layout as fmt_row."""
    plain_row = "{:>12}  {:<16}  {}  {:<{ow}}  {:<4}  {:<{rw}}  {}".format(
        human_size(size), fmt_mtime(mtime),
        _tag_plain(SVN_WC),
        owner, "DIR ",
        SVN_RULE_ID,
        abs_path,
        ow=_OWNER_WIDTH, rw=_RULE_WIDTH,
    )
    color_row = "{:>12}  {:<16}  {}  {:<{ow}}  {:<4}  {:<{rw}}  {}".format(
        human_size(size), fmt_mtime(mtime),
        _tag_color(SVN_WC),
        owner, "DIR ",
        SVN_RULE_ID,
        abs_path,
        ow=_OWNER_WIDTH, rw=_RULE_WIDTH,
    )
    with _emit_lock:
        _clear_progress()
        print(color_row)
        _write_fh(scan_fh, plain_row)
        _write_fh(svn_fh,  plain_row)
        if cur_dir:
            _progress(cur_dir)
def scan_and_print(root, level_filter, scan_fh, error_fh, svn_fh,
                   trace_path, error_path, svn_path, stats, jobs=4):
    # type: (Path, Optional[Set[str]], object, object, object, str, str, str, Stats, int) -> List[Tuple]
    """
    Walk the tree, classify entries, and emit results.

    Parallelism strategy (option B -- emit in completion order):
    - os.walk runs on the main thread.
    - For every matched DIRECTORY, dir_total_size() is submitted to a
      ThreadPoolExecutor (--jobs workers).  The Future is stored in
      pending_futures.
    - During each walk iteration we do a non-blocking sweep of pending_futures
      and emit any that have already finished.
    - After the walk loop, we drain all remaining pending_futures using
      as_completed(), emitting each row as it finishes.
    - FILES are emitted immediately (no expensive size calc needed).
    - SVN dirs also use the pool (their callback emits directly).

    Result tuples:
      (size, mtime, action_level, tag_key, owner, ftype, rule_id, abs_path)
    """
    root_real    = Path(os.path.realpath(str(root)))
    results      = []          # type: List[Tuple]
    counts       = {lv: 0 for lv in ALL_LEVELS}  # type: Dict[str, int]
    results_lock = threading.Lock()
    cur_dir      = ""

    with _emit_lock:
        _clear_progress()
        print(_c(HEADER_PLAIN, "bold"))
        print(SEP)
        _write_fh(scan_fh, HEADER_PLAIN)
        _write_fh(scan_fh, SEP)
        print(_c("  log-trace : {}".format(trace_path if trace_path else "(none)"), "dim"))
        print(_c("  log-error : {}".format(error_path if error_path else "(none)"), "dim"))
        print(_c("  log-svndir: {}".format(svn_path   if svn_path   else "(none)"), "dim"))
        print()

    # ------------------------------------------------------------------
    #  emit_dir_result: called when a dir_total_size Future completes
    # ------------------------------------------------------------------
    def emit_dir_result(fut, meta):
        # type: (_futures.Future, dict) -> None
        try:
            size = fut.result()
        except Exception as exc:
            _log_error(error_fh, meta["abs_path"], exc)
            return
        if size < 0:
            return  # interrupted

        tag_key   = meta["tag_key"]
        action_lv = meta["action_lv"]
        emit_row(
            fmt_row(size, meta["mt"], tag_key, meta["owner"],
                    "D", meta["rule_id"], meta["abs_path"], for_file=False),
            fmt_row(size, meta["mt"], tag_key, meta["owner"],
                    "D", meta["rule_id"], meta["abs_path"], for_file=True),
            scan_fh, meta["scan_cur"],
        )
        with results_lock:
            results.append((size, meta["mt"], action_lv, tag_key,
                            meta["owner"], "D", meta["rule_id"],
                            Path(meta["abs_path"])))
            counts[action_lv] += 1
            stats.record_scan(meta["rule_id"], size)

    # ------------------------------------------------------------------
    #  Walk + pool
    # ------------------------------------------------------------------
    pending = []  # type: List[Tuple]   # (Future, meta)

    def sweep_pending():
        # type: () -> None
        """Emit any already-finished pending futures (non-blocking)."""
        still = []
        for f, m in pending:
            if f.done():
                emit_dir_result(f, m)
            else:
                still.append((f, m))
        pending[:] = still

    with _futures.ThreadPoolExecutor(max_workers=jobs) as pool:

        for dirpath, dirnames, filenames in os.walk(
                str(root), followlinks=False, onerror=lambda e: None):
            if _interrupted:
                dirnames[:] = []
                break

            dp      = Path(dirpath)
            cur_dir = dirpath
            with _emit_lock:
                _progress(cur_dir)

            sweep_pending()   # opportunistic: emit dirs whose size is ready

            # ---- directories ----
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

                # SVN detection (highest priority -- prune before classify)
                if is_svn_wc(full):
                    dirnames.remove(dname)   # prune so os.walk never enters
                    if _interrupted:
                        break
                    try:
                        st    = full.stat()
                        mt    = st.st_mtime
                        owner = get_owner(full)
                    except OSError as exc:
                        _log_error(error_fh, str(full), exc)
                        continue
                    abs_path = str(root_real / full.relative_to(root))
                    # Capture loop variables for the callback closure
                    _mt, _owner, _ap = mt, owner, abs_path
                    _cd  = cur_dir
                    _sfh = svn_fh
                    _scfh = scan_fh

                    def _svn_cb(fut, mt=_mt, owner=_owner, ap=_ap,
                                cd=_cd, sfh=_sfh, scfh=_scfh):
                        # type: (...) -> None
                        try:
                            sz = fut.result()
                        except Exception:
                            sz = 0
                        if sz < 0:
                            sz = 0
                        emit_svn_row(sz, mt, owner, ap, sfh, scfh, cd)
                        stats.record_svn(sz)

                    pool.submit(dir_total_size, full).add_done_callback(_svn_cb)
                    continue

                result = classify(dname, dp, is_dir=True)
                if result is None:
                    continue
                tag_key, _desc, rule_id = result
                action_lv = _action_level(tag_key)
                dirnames.remove(dname)   # prune matched dir

                if level_filter and action_lv not in level_filter:
                    continue
                if _interrupted:
                    break

                try:
                    st    = full.stat()
                    mt    = st.st_mtime
                    owner = get_owner(full)
                except OSError as exc:
                    _log_error(error_fh, str(full), exc)
                    continue

                abs_path = str(root_real / full.relative_to(root))
                meta = {
                    "tag_key":   tag_key,
                    "action_lv": action_lv,
                    "owner":     owner,
                    "rule_id":   rule_id,
                    "abs_path":  abs_path,
                    "mt":        mt,
                    "scan_cur":  cur_dir,
                }
                fut = pool.submit(dir_total_size, full)
                pending.append((fut, meta))

            # ---- files (emit immediately) ----
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
                tag_key, _desc, rule_id = result
                action_lv = _action_level(tag_key)

                if level_filter and action_lv not in level_filter:
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
                    fmt_row(size, mt, tag_key, owner, "F", rule_id,
                            abs_path, for_file=False),
                    fmt_row(size, mt, tag_key, owner, "F", rule_id,
                            abs_path, for_file=True),
                    scan_fh, cur_dir,
                )
                with results_lock:
                    results.append((size, mt, action_lv, tag_key, owner,
                                    "F", rule_id, Path(abs_path)))
                    counts[action_lv] += 1
                    stats.record_scan(rule_id, size)

        # Walk finished -- drain remaining pending dir futures as they complete
        if pending:
            future_map = {f: m for f, m in pending}
            for fut in _futures.as_completed(future_map):
                emit_dir_result(fut, future_map[fut])

    # pool.__exit__ waits for all submitted tasks (including SVN callbacks)

    with _emit_lock:
        _clear_progress()

    total_size  = sum(r[0] for r in results)
    total_count = len(results)
    partial     = "  [PARTIAL - scan interrupted]" if _interrupted else ""

    summary = (
        "Total {} items  |  "
        "Safe: {}  Gzip: {}  Protected: {}  Current(keep): {}  SVN-WC: {}  |  "
        "Est. size: {}{}"
    ).format(
        total_count,
        counts[SAFE], counts[GZIP], counts[PROTECTED], counts[CURRENT],
        stats.svn_count,
        human_size(total_size), partial,
    )

    with _emit_lock:
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

    for _size, _mt, effective, tag_key, owner, ftype, rule_id, path in actionable:
        if _interrupted:
            msg = "  [INTERRUPTED] actions aborted."
            print(_c(msg, "yellow"))
            _write_fh(delete_fh, msg)
            break

        row_plain = fmt_row(_size, _mt, tag_key, owner, ftype, rule_id,
                            str(path), for_file=True)
        row_term  = fmt_row(_size, _mt, tag_key, owner, ftype, rule_id,
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

    mode   = "DRY-RUN" if dry_run else "EXECUTED"
    # Column widths for summary rule table
    _SW_ID    = 6
    _SW_TAG   = _TAG_W      # 12 -- same as trace log tag width
    _SW_DESC  = 30
    _SW_HITS  = 8
    _SW_SIZE  = 12
    _SW_PAT   = 36
    _sum_sep  = "-" * (_SW_ID + _SW_TAG + _SW_DESC + _SW_HITS + _SW_SIZE + _SW_PAT + 14)

    def _sum_hdr():
        # type: () -> str
        return "{:<{i}}  {:<{t}}  {:<{d}}  {:>{h}}  {:>{s}}  {}".format(
            "ID", "LEVEL", "DESC", "HITS", "EST.SIZE", "PATTERN",
            i=_SW_ID, t=_SW_TAG, d=_SW_DESC, h=_SW_HITS, s=_SW_SIZE)

    def _sum_row(rid, tag, desc, hits, size, pattern):
        # type: (str, str, str, int, int, str) -> str
        return "{:<{i}}  {:<{t}}  {:<{d}}  {:>{h}}  {:>{s}}  {}".format(
            rid, tag, desc[:_SW_DESC], hits, human_size(size), pattern,
            i=_SW_ID, t=_SW_TAG, d=_SW_DESC, h=_SW_HITS, s=_SW_SIZE)

    lines = [
        "# IC Cleanup -- summary log",
        "# Date  : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "# Root  : {}".format(root_real),
        "# Mode  : {}".format(mode),
        "",
        "=== Rule Hit Count ===",
        _sum_hdr(),
        _sum_sep,
    ]

    any_hit = False
    for r in rules:
        info = stats.rule_hits.get(r["id"], {"hits": 0, "size": 0})
        if info["hits"] == 0:
            continue
        any_hit = True
        # For CURRENT rules the tag shown in trace varies (_ncur_safe / _ncur_keep),
        # but in the summary we show the rule-level tag (CURRENT = [KEEP(CURR)])
        # which is the umbrella; individual split is visible in trace log.
        level_const = r["level"]
        tag_str = _PLAIN.get(level_const, _mk_tag(level_const)).strip()
        lines.append(_sum_row(
            r["id"], tag_str, r["desc"],
            info["hits"], info["size"], r["pattern"]))

    # SVN implicit rule row
    if stats.svn_count > 0:
        any_hit = True
        lines.append(_sum_row(
            SVN_RULE_ID, _PLAIN[SVN_WC].strip(), "SVN working copy",
            stats.svn_count, stats.svn_size, ".svn (implicit)"))

    if not any_hit:
        lines.append("  (no rules matched)")
    lines.append(_sum_sep)

    total_hits = sum(v["hits"] for v in stats.rule_hits.values()) + stats.svn_count
    total_size = sum(v["size"] for v in stats.rule_hits.values()) + stats.svn_size
    lines.append(_sum_row("TOTAL", "", "", total_hits, total_size, ""))

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
    p.add_argument("--jobs", metavar="N", type=int, default=4,
        help="Parallel threads for directory size calculation (default: 4)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output: safe gzip protected current")
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
        _write_fh(svn_fh, HEADER_PLAIN)
        _write_fh(svn_fh, SEP)

    try:
        results = scan_and_print(root, level_filter,
                                 scan_fh, error_fh, svn_fh,
                                 trace_p, error_p, svn_p, stats,
                                 jobs=args.jobs)
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
