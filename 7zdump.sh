#!/usr/bin/env bash
# 7zdump.sh — compress + encrypt a file with 7z, then hexdump it
# Usage: 7zdump.sh <filename> [-enc <password>]
#
# Output: <filename>.7z.hex  (hexdump, 128 hex chars per line)
# The .7z is created with AES-256 + -mhe=on (header encryption)
# and removed after dumping unless -keep is passed.

set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────
usage() {
  echo "Usage: $(basename "$0") <filename> [-enc <password>] [-keep] [-o <outfile>]"
  echo ""
  echo "  <filename>        File to compress and encrypt"
  echo "  -enc <password>   Encryption password (prompted if omitted)"
  echo "  -keep             Keep the intermediate .7z file"
  echo "  -o <outfile>      Output hex file path (default: <filename>.7z.hex)"
  exit 1
}

die() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*"; }

# ── parse args ────────────────────────────────────────────────────────
[[ $# -lt 1 ]] && usage

INPUT="$1"; shift
PASSWORD=""
KEEP=0
OUTFILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -enc)
      [[ $# -lt 2 ]] && die "-enc requires a password argument"
      PASSWORD="$2"; shift 2 ;;
    -keep)
      KEEP=1; shift ;;
    -o)
      [[ $# -lt 2 ]] && die "-o requires a filename argument"
      OUTFILE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── validate ──────────────────────────────────────────────────────────
[[ -f "$INPUT" ]] || die "File not found: $INPUT"
command -v 7z    >/dev/null 2>&1 || die "7z not found. Install p7zip-full (apt) or p7zip (yum/brew)"
command -v hexdump >/dev/null 2>&1 || die "hexdump not found"

BASENAME="$(basename "$INPUT")"
ARCHIVE="${INPUT}.7z"
[[ -z "$OUTFILE" ]] && OUTFILE="${INPUT}.7z.hex"

# ── prompt password if not provided ──────────────────────────────────
if [[ -z "$PASSWORD" ]]; then
  read -rsp "[PASS]  Enter encryption password: " PASSWORD; echo
  read -rsp "[PASS]  Confirm password:           " PASSWORD2; echo
  [[ "$PASSWORD" == "$PASSWORD2" ]] || die "Passwords do not match"
  [[ -z "$PASSWORD" ]] && die "Password cannot be empty"
fi

# ── compress + encrypt ────────────────────────────────────────────────
info "Compressing and encrypting: $INPUT"
info "Output archive:  $ARCHIVE"

7z a \
  -t7z \
  -m0=lzma2 \
  -mx=9 \
  -mhe=on \
  -p"${PASSWORD}" \
  -- "$ARCHIVE" "$INPUT" \
  > /dev/null

ORIG_SIZE=$(stat -c%s "$INPUT"   2>/dev/null || stat -f%z "$INPUT")
ARCH_SIZE=$(stat -c%s "$ARCHIVE" 2>/dev/null || stat -f%z "$ARCHIVE")
info "Original size:   $ORIG_SIZE bytes"
info "Archive size:    $ARCH_SIZE bytes"

# ── hexdump ───────────────────────────────────────────────────────────
# Format:
#   - Each data line:  1 leading space + 128 hex chars
#   - Blank line before first data line
#   - Blank line after every 32 data lines
#   - Blank line after last data line
info "Hexdumping to:   $OUTFILE"

{
  echo ""                                          # leading blank line
  hexdump -v -e '64/1 "%02x"' -e '"\n"' "$ARCHIVE" | \
  awk '{
    if (NR % 32 == 1 && NR > 1) print ""          # blank line every 32 rows
    print " " $0                                   # leading space
  }'
  echo ""                                          # trailing blank line
} > "$OUTFILE"

HEX_LINES=$(wc -l < "$OUTFILE")
info "Hex lines:       $HEX_LINES"

# ── cleanup ───────────────────────────────────────────────────────────
if [[ $KEEP -eq 0 ]]; then
  rm -f "$ARCHIVE"
  info "Removed:         $ARCHIVE"
else
  info "Kept:            $ARCHIVE"
fi

echo ""
echo "Done. Transfer this file to Windows and use the HTML tool to restore:"
echo "  $OUTFILE"
