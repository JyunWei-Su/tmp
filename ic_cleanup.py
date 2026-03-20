#!/cld/tools/python3.8.8/bin/python3.8
"""
IC Design Project File Cleanup & Risk Classification Tool

Usage:
    ic_cleanup.py <scan_root> [options]

Options:
    --rules FILE         JSON rule file (default: rules.json beside this script)
    --out-dir DIR        Write all logs under DIR:
                           DIR/trace.log   -- scan results  (with rule IDs)
                           DIR/delete.log  -- delete actions
                           DIR/error.log   -- filesystem errors
                           DIR/rule.log    -- loaded rule table with IDs
    --gz                 Compress all --out-dir logs with gzip (.log.gz)
    --log-trace  FILE    Scan trace log  (overrides --out-dir; .gz = gzip)
    --log-delete FILE    Delete log      (overrides --out-dir; .gz = gzip)
    --log-error  FILE    Error log       (overrides --out-dir; .gz = gzip)
    --log-rule   FILE    Rule table log  (overrides --out-dir; .gz = gzip)
    --delete             Actually delete files (default: dry-run, list only)
    --level LEVEL [...]  Show only specific risk level(s):
                           safe | caution | danger | protected | not_current

Rule JSON format (see rules.json):
    {
      "rules": [
        {
          "pattern":  "<Python regex against basename>",   required
          "type":     "f" | "d" | "fd",                   required
          "level":    "safe|caution|danger|protected|not_current",  required
          "ancestor": "<Python regex against any ancestor dir>",    optional
          "desc":     "<human label>"                               optional
        },
        ...
      ]
    }
    Rules are evaluated top-to-bottom; first match wins.
    Rule IDs (R001, R002, ...) are auto-assigned after loading.
    Every matched item records its rule ID in all logs.
"""

import argparse
import gzip
import io
import json
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

# Map JSON level string -> internal constant
_LEVEL_FROM_JSON = {
    "safe":        SAFE,
    "caution":     CAUTION,
    "danger":      DANGER,
    "protected":   PROTECTED,
    "not_current": NOT_CURRENT,
}

LEVEL_MAP = _LEVEL_FROM_JSON   # alias for CLI --level filter


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
#  Rule loading from JSON
#  After loading, every rule dict gets:
#    "id"          : "R001", "R002", ...
#    "_pat_re"     : compiled pattern regex
#    "_ancestor_re": compiled ancestor regex or None
# ===========================================================================
RULES = []  # type: List[Dict]


def load_rules(json_path):
    # type: (str) -> List[Dict]
    """Load rules from a JSON file, assign IDs, compile regexes.
    Raises SystemExit on any error so the caller doesn't need to check."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        print("ERROR: cannot load rules from {}: {}".format(json_path, exc),
              file=sys.stderr)
        sys.exit(1)

    raw = data.get("rules")
    if not isinstance(raw, list) or not raw:
        print("ERROR: rules.json must contain a non-empty 'rules' list",
              file=sys.stderr)
        sys.exit(1)

    loaded = []  # type: List[Dict]
    for idx, entry in enumerate(raw, start=1):
        rule_id  = "R{:03d}".format(idx)
        pattern  = entry.get("pattern", "")
        rtype    = entry.get("type",    "fd")
        level_s  = entry.get("level",  "safe").lower().replace("-", "_")
        ancestor = entry.get("ancestor", None)
        desc     = entry.get("desc", "")

        if level_s not in _LEVEL_FROM_JSON:
            print("ERROR: rule {} has unknown level '{}' (valid: {})".format(
                rule_id, level_s, list(_LEVEL_FROM_JSON.keys())), file=sys.stderr)
            sys.exit(1)

        try:
            pat_re = re.compile(pattern)
        except re.error as exc:
            print("ERROR: rule {} pattern '{}' is invalid regex: {}".format(
                rule_id, pattern, exc), file=sys.stderr)
            sys.exit(1)

        anc_re = None
        if ancestor:
            try:
                anc_re = re.compile(ancestor)
            except re.error as exc:
                print("ERROR: rule {} ancestor '{}' is invalid regex: {}".format(
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
    """Write the loaded rule table (with IDs) to a log file handle."""
    if fh is None:
        return
    _write_fh(fh, "# IC Cleanup -- rule table")
    _write_fh(fh, "# Generated: {}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    _write_fh(fh, "# Total rules: {}".format(len(rules)))
    _write_fh(fh, "")
    hdr = "{:<6}  {:<12}  {:<4}  {:<20}  {:<30}  {}".format(
        "ID", "LEVEL", "TYPE", "ANCESTOR", "DESC", "PATTERN")
    sep = "-" * 100
    _write_fh(fh, hdr)
    _write_fh(fh, sep)
    for r in rules:
        _write_fh(fh, "{:<6}  {:<12}  {:<4}  {:<20}  {:<30}  {}".format(
            r["id"],
            r["level"],
            r["type"],
            r["ancestor"] or "(any)",
            r["desc"],
            r["pattern"],
        ))
    _write_fh(fh, sep)


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
#  Classification  -- returns (internal_sentinel, desc, rule_id) or None
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


# ---------------------------------------------------------------------------
#  Column layout
#  RULE column is fixed at 6 chars ("R001  " etc.) -- same as rule ID width
# ---------------------------------------------------------------------------
_TAG_COL_W   = len(list(_PLAIN.values())[0])
_OWNER_WIDTH = 12
_RULE_WIDTH  = 6    # "R001" + 2 spaces padding handled by format spec

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
        human_size(size),
        fmt_mtime(mtime),
        tag,
        owner,
        ftype_str,
        rule_id,
        abs_path,
        ow=_OWNER_WIDTH,
        rw=_RULE_WIDTH,
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
    """Open a log for line-by-line UTF-8 writing.
    .gz suffix -> vim-compatible single-stream gzip (mtime=0)."""
    if path.endswith(".gz"):
        raw = open(path, "wb")
        gz  = gzip.GzipFile(filename="", mode="wb", compresslevel=6,
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
    Result tuples:
      (size, mtime, effective_level, internal, owner, ftype, rule_id, abs_path)
    """
    root_real = Path(os.path.realpath(str(root)))

    _clear_progress()
    print(_c(HEADER_PLAIN, "bold"))
    print(SEP)
    _write_fh(scan_fh, HEADER_PLAIN)
    _write_fh(scan_fh, SEP)

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
                mt    = 0.0
                owner = "?"

            abs_path = str(root_real / full.relative_to(root))
            emit_row(
                fmt_row(size, mt, internal, owner, "D", rule_id, abs_path, for_file=False),
                fmt_row(size, mt, internal, owner, "D", rule_id, abs_path, for_file=True),
                scan_fh, cur_dir,
            )
            results.append((size, mt, effective, internal, owner, "D", rule_id, Path(abs_path)))
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
#  Delete
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

    for _size, _mt, effective, internal, owner, ftype, rule_id, path in deletable:
        if _interrupted:
            msg = "  [INTERRUPTED] delete aborted."
            print(_c(msg, "yellow"))
            _write_fh(delete_fh, msg)
            break

        row_plain = fmt_row(_size, _mt, internal, owner, ftype, rule_id,
                            str(path), for_file=True)
        row_term  = fmt_row(_size, _mt, internal, owner, ftype, rule_id,
                            str(path), for_file=False)

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
#  CLI helpers
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
        help="Write trace/delete/error/rule logs under DIR")
    p.add_argument("--gz", action="store_true", default=False,
        help="Compress all --out-dir logs with gzip (.log.gz)")

    p.add_argument("--log-trace",  metavar="FILE", default=None, dest="log_trace",
        help="Scan trace log  (overrides --out-dir; .gz = gzip)")
    p.add_argument("--log-delete", metavar="FILE", default=None, dest="log_delete",
        help="Delete action log (overrides --out-dir; .gz = gzip)")
    p.add_argument("--log-error",  metavar="FILE", default=None, dest="log_error",
        help="Filesystem error log (overrides --out-dir; .gz = gzip)")
    p.add_argument("--log-rule",   metavar="FILE", default=None, dest="log_rule",
        help="Rule table log (overrides --out-dir; .gz = gzip)")

    p.add_argument("--delete", action="store_true", default=False,
        help="Actually delete Safe/Caution items (default: dry-run)")
    p.add_argument("--level", metavar="LEVEL", nargs="+", default=None,
        choices=list(LEVEL_MAP.keys()),
        help="Filter output: safe caution danger protected not_current")
    return p


def _resolve_log_paths(args):
    # type: (argparse.Namespace) -> Tuple[str, str, str, str]
    """Return (trace, delete, error, rule) as absolute path strings or ''."""
    ext = ".gz" if args.gz else ""

    def _from_dir(name):
        # type: (str) -> str
        if args.out_dir:
            return str(Path(args.out_dir).resolve() / (name + ".log" + ext))
        return ""

    trace_p  = str(Path(args.log_trace ).resolve()) if args.log_trace  else _from_dir("trace")
    delete_p = str(Path(args.log_delete).resolve()) if args.log_delete else _from_dir("delete")
    error_p  = str(Path(args.log_error ).resolve()) if args.log_error  else _from_dir("error")
    rule_p   = str(Path(args.log_rule  ).resolve()) if args.log_rule   else _from_dir("rule")
    return trace_p, delete_p, error_p, rule_p


def _open_log_safe(path, label):
    # type: (str, str) -> Optional[object]
    if not path:
        return None
    try:
        return open_log(path)
    except OSError as exc:
        print("ERROR: cannot open {}: {}".format(label, exc), file=sys.stderr)
        return None


# ===========================================================================
#  main
# ===========================================================================
def main():
    # type: () -> None
    _install_sigint_handler()

    args = build_parser().parse_args()

    # --- locate rule file ---
    if args.rules_file:
        rules_path = args.rules_file
    else:
        rules_path = str(Path(__file__).resolve().parent / "rules.json")

    if not os.path.exists(rules_path):
        print("ERROR: rule file not found: {}".format(rules_path), file=sys.stderr)
        sys.exit(1)

    # --- load + compile rules ---
    global RULES
    RULES = load_rules(rules_path)
    print("Loaded {} rules from {}".format(
        len(RULES), _c(rules_path, "cyan")))

    # --- scan root ---
    root = Path(args.root).resolve()
    if not root.exists():
        print("ERROR: directory not found: {}".format(root), file=sys.stderr)
        sys.exit(1)

    # --- create out-dir ---
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

    trace_p, delete_p, error_p, rule_p = _resolve_log_paths(args)

    scan_fh   = _open_log_safe(trace_p,  "--log-trace")
    error_fh  = _open_log_safe(error_p,  "--log-error")
    delete_fh = _open_log_safe(delete_p, "--log-delete")
    rule_fh   = _open_log_safe(rule_p,   "--log-rule")

    # --- write rule log ---
    write_rule_log(RULES, rule_fh)
    if rule_fh:
        rule_fh.close()   # type: ignore
        print("Rule log        : {}".format(_c(rule_p, "cyan")))

    # --- write scan log header ---
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

    try:
        results = scan_and_print(root, level_filter,
                                 scan_fh, error_fh,
                                 trace_p, error_p)
    finally:
        if scan_fh:
            scan_fh.close()   # type: ignore
            print("\nScan trace log  : {}".format(_c(trace_p, "cyan")))
        if error_fh:
            error_fh.close()  # type: ignore
            print("Error log       : {}".format(_c(error_p, "cyan")))

    if not results:
        print("\nNo matching files found.")
        if delete_fh:
            delete_fh.close()  # type: ignore
        return

    print()
    try:
        do_delete(results, dry_run=not args.delete,
                  delete_fh=delete_fh, error_fh=error_fh,
                  delete_path=delete_p)
    finally:
        if delete_fh:
            delete_fh.close()  # type: ignore
            print("\nDelete log      : {}".format(_c(delete_p, "cyan")))

    if _interrupted:
        sys.exit(130)


if __name__ == "__main__":
    main()
