#!/bin/bash
#===============================================================================
# lipsum.sh — generate real English sample text with UTF-8 richness
#
# Usage:  ./lipsum.sh [SIZE] [OUTPUT_FILE]
#         ./lipsum.sh -s 500K > sample.txt
#         ./lipsum.sh 2M output.txt
#
# SIZE accepts K/M/G suffix (default: 1M = 1 megabyte).
# Output goes to the named file, or stdout if no file is given.
#===============================================================================

set -euo pipefail

# --- defaults ---------------------------------------------------------------
SIZE="1M"
OUTFILE=""

# --- helpers ----------------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }

parse_size() {
  local raw="$1"
  local num="${raw%[KkMmGg]}"
  local suf="${raw##*[0-9.]}"
  [[ "$num" =~ ^[0-9]+$ ]] || die "invalid size: $raw"
  case "$suf" in
    [Kk]) echo $(( num * 1024 )) ;;
    [Mm]) echo $(( num * 1024 * 1024 )) ;;
    [Gg]) echo $(( num * 1024 * 1024 * 1024 )) ;;
    "")   echo "$num" ;;
    *)    die "unknown size suffix in: $raw (use K, M, or G)" ;;
  esac
}

# --- argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--size) SIZE="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^$/s/^# //p' "$0"; exit 0 ;;
    -*) die "unknown flag: $1" ;;
    *)
      if [[ "$1" =~ ^[0-9]+[KkMmGg]?$ ]]; then SIZE="$1"
      elif [[ -z "$OUTFILE" ]]; then OUTFILE="$1"
      else die "unexpected argument: $1"; fi
      shift ;;
  esac
done

MAX_BYTES=$(parse_size "$SIZE")

DICT="/usr/share/dict/words"
[[ -f "$DICT" ]] || die "dictionary not found at $DICT"

# --- pre-filter word lists (one-time cost) ----------------------------------
echo "Loading words..." >&2
WORDS_A=$(grep -E '^[a-z]{2,7}$' "$DICT")
WORDS_B=$(grep -E '^[A-Z][a-z]{2,9}$' "$DICT")

echo "Generating $(numfmt --to=iec "$MAX_BYTES" 2>/dev/null || echo "$MAX_BYTES bytes")..." >&2

# --- output redirect --------------------------------------------------------
if [[ -n "$OUTFILE" ]]; then exec > "$OUTFILE"; fi

# --- awk core (zero subshells — one process, pure speed) --------------------
# Pipe word lists into awk via stdin: first pool A, then a sentinel, then pool B.
{
  printf '%s\n' "$WORDS_A"
  echo "---SENTINEL---"
  printf '%s\n' "$WORDS_B"
} | gawk -v MAX_BYTES="$MAX_BYTES" '
BEGIN {
  srand()

  cnt_a = 0; cnt_b = 0
  reading_b = 0
}

# Read stdin line by line: build arrays.
{
  if ($0 == "---SENTINEL---") {
    reading_b = 1
    next
  }
  if (!reading_b) {
    if ($0 != "") words_a[cnt_a++] = $0
  } else {
    if ($0 != "") words_b[cnt_b++] = $0
  }
}

END {
  # Safety: if word lists empty, die
  if (cnt_a == 0) {
    print "ERROR: no words loaded" > "/dev/stderr"
    exit 1
  }

  # --- UTF-8 sprinkles: code-point → UTF-8 converter --------------------
  # Instead of a static list, we define ranges spread across the
  # ENTIRE Unicode spectrum (U+0080 through U+10FFFD, skipping
  # surrogates U+D800–U+DFFF and noncharacters U+xxFFFE–xxFFFF).
  # Each range contributes proportionally to its span so the output
  # covers the full numerical breadth of Unicode.

  # --- init full-spectrum UTF-8 sprinkle ranges -------------------------
  split("", ranges_lo)
  split("", ranges_hi)
  rc = 0                # range count
  total_span = 0        # sum of (hi - lo + 1) across all ranges

  # Spread across the entire valid Unicode spectrum (~20 bands).
  # We exclude surrogates and noncharacters but include private-use.
  # --- BMP (plane 0) in ~16K-wide bands, skipping surrogates ---
  add_range(0x00A0, 0x3FFF)    # Latin/Greek/Cyrillic/misc
  add_range(0x4000, 0x7FFF)    # CJK Unified Ideographs
  add_range(0x8000, 0xD7FF)    # CJK + Hangul + rest of BMP pre-surrogate
  # Skip surrogates 0xD800-0xDFFF
  add_range(0xE000, 0xFFEF)    # Private Use + CJK compat + halfwidth
  # --- SMP (plane 1) -------------------------------------------
  add_range(0x10000, 0x1FFFF)  # Linear B, musical, math alphanum, emoji
  # --- SIP (plane 2) -------------------------------------------
  add_range(0x20000, 0x2FFFF)  # CJK Extension B + compat ideographs
  # --- Higher planes (3-16) — smaller slices -------------------
  add_range(0x30000, 0x3FFFF)
  add_range(0x40000, 0x4FFFF)
  add_range(0x50000, 0x5FFFF)
  add_range(0x60000, 0x6FFFF)
  add_range(0x70000, 0x7FFFF)
  add_range(0x80000, 0x8FFFF)
  add_range(0x90000, 0x9FFFF)
  add_range(0xA0000, 0xAFFFF)
  add_range(0xB0000, 0xBFFFF)
  add_range(0xC0000, 0xCFFFF)
  add_range(0xD0000, 0xDFFFF)
  add_range(0xE0000, 0xEFFFF)
  add_range(0xF0000, 0xFFFFF)
  add_range(0x100000, 0x10FFFF)

  # --- punctuation arrays ------------------------------------------------
  split(". . . . . ? !", periods, " ")
  pcnt = length(periods)
  split(", , , , , ; :  —   – ", commas, " ")
  ccnt = length(commas)
  split("( [ { \" \x27 «", lparens, " ")
  split(") ] } \" \x27 »", rparens, " ")
  lcnt = length(lparens)

  # --- output buffer ------------------------------------------------------
  buf = ""
  bytes_out = 0
  para_count = 0

  while (bytes_out < MAX_BYTES) {
    para = paragraph()
    para = para "\n"
    printf "%s", para
    bytes_out += length(para) + 1   # +1 for the newline we printed
    para_count++
  }

  # stderr progress
  system("")  # flush
}

# --- helpers ---------------------------------------------------------------

function pick_a() { return words_a[int(rand() * cnt_a)] }
function pick_b() { return words_b[int(rand() * cnt_b)] }

# --- UTF-8-range management ----------------------------------------------
function add_range(lo, hi) {
  rc++
  ranges_lo[rc] = lo
  ranges_hi[rc] = hi
  total_span += (hi - lo + 1)
}

# Encode a Unicode code point to UTF-8 bytes.
function cp_to_utf8(cp,   b1,b2,b3,b4) {
  if (cp < 0x80) {
    return sprintf("%c", cp)
  } else if (cp < 0x800) {
    b1 = 0xC0 + int(cp / 0x40)
    b2 = 0x80 + (cp % 0x40)
    return sprintf("%c%c", b1, b2)
  } else if (cp < 0x10000) {
    b1 = 0xE0 + int(cp / 0x1000)
    b2 = 0x80 + (int(cp / 0x40) % 0x40)
    b3 = 0x80 + (cp % 0x40)
    return sprintf("%c%c%c", b1, b2, b3)
  } else {
    b1 = 0xF0 + int(cp / 0x40000)
    b2 = 0x80 + (int(cp / 0x1000) % 0x40)
    b3 = 0x80 + (int(cp / 0x40) % 0x40)
    b4 = 0x80 + (cp % 0x40)
    return sprintf("%c%c%c%c", b1, b2, b3, b4)
  }
}

# Pick a random valid code point across the full Unicode spectrum.
function random_codepoint(   pos, i, lo, hi, span, cp) {
  pos = int(rand() * total_span)
  for (i = 1; i <= rc; i++) {
    lo = ranges_lo[i] + 0
    hi = ranges_hi[i] + 0
    span = hi - lo + 1
    if (pos < span) {
      cp = lo + pos
      # Skip noncharacters: U+FDD0-U+FDEF and U+xxFFFE-U+xxFFFF
      if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp % 0x10000) >= 0xFFFE) {
        return random_codepoint()   # retry (vanishingly rare)
      }
      return cp
    }
    pos -= span
  }
  return 0xFFFD   # fallback: replacement character
}

function sprinkle() {
  return cp_to_utf8(random_codepoint())
}

function np(   r) {
  r = int(rand() * 6)
  if (r == 0) return pick_a()
  if (r == 1) return pick_a() " " pick_a()
  if (r == 2) return "the " pick_a()
  if (r == 3) return "the " pick_a() " " pick_a()
  if (r == 4) return "a " pick_a()
  return "a " pick_a() " " pick_a()
}

function vp(   r) {
  r = int(rand() * 5)
  if (r == 0) return pick_a()
  if (r == 1) return pick_a() " " pick_a()
  if (r == 2) return pick_a() " the " pick_a()
  if (r == 3) return pick_a() " a " pick_a()
  return "will " pick_a() " the " pick_a()
}

function cap(str) {
  return toupper(substr(str, 1, 1)) substr(str, 2)
}

function sprinkle_text(text,   n, words, wc, s, pos, sp, j, out) {
  n = int(rand() * 3)   # 0, 1, or 2 sprinkles
  if (n == 0) return text

  wc = split(text, words, " ")
  if (wc <= 2) return text

  for (s = 0; s < n; s++) {
    pos = 1 + int(rand() * (wc - 1))
    sp = sprinkle()
    out = ""
    for (j = 1; j < pos; j++) out = out words[j] " "
    out = out sp
    for (j = pos; j <= wc; j++) out = out " " words[j]
    text = out
    wc = split(text, words, " ")
  }
  return text
}

function sentence(   s, prep, conj, di, lparen, rparen, comma, words, wc, i, pos, left, right) {
  s = cap(np()) " " vp()

  # ~40% object phrase
  if (rand() < 0.4) s = s " " np()

  # ~30% prepositional phrase
  if (rand() < 0.3) {
    prep = substr("in on at with from by under", 1 + int(rand() * 8) * 5, 5)
    gsub(/ /, "", prep)
    s = s " " prep " the " pick_a()
  }

  # ~10% extra clause
  if (rand() < 0.1) {
    conj = (int(rand() * 3) == 0 ? "and" : (int(rand() * 3) == 1 ? "but" : "because"))
    s = s " " conj " " np() " " vp()
  }

  # ~15% adverb prefix
  if (rand() < 0.15) s = pick_a() "ly " s

  # ~8% wrap in paired delimiters
  if (rand() < 0.08) {
    di = 1 + int(rand() * lcnt)
    lparen = lparens[di]
    rparen = rparens[di]
    pos = index(s, " ")
    if (pos > 0) {
      s = substr(s, 1, pos) lparen substr(s, pos + 1) rparen
    }
  }

  # ~5% em-dash parenthetical
  if (rand() < 0.05) s = s " — " pick_a() " " pick_a() " — " pick_a()

  # ~20% intra-sentence punctuation
  if (rand() < 0.2) {
    comma = commas[1 + int(rand() * ccnt)]
    wc = split(s, words, " ")
    if (wc > 3) {
      pos = int(wc / 2) + int(rand() * (wc / 2))
      left = ""; right = ""
      for (i = 1; i < pos; i++) left = left words[i] " "
      for (i = pos; i <= wc; i++) right = right " " words[i]
      s = left comma right
    }
  }

  # ~40% UTF-8 sprinkle
  if (rand() < 0.4) s = sprinkle_text(s)

  # ending punctuation
  s = s periods[1 + int(rand() * pcnt)] " "
  return s
}

function paragraph(   n, out, i, bullets) {
  n = 2 + int(rand() * 7)
  out = ""
  for (i = 0; i < n; i++) out = out sentence()

  # ~10% bullet list
  if (rand() < 0.1) {
    out = out "\n"
    bullets = 1 + int(rand() * 4)
    for (i = 0; i < bullets; i++) {
      out = out "  • " np() " " vp() " — " periods[1 + int(rand() * pcnt)] "\n"
    }
  }
  # ~5% horizontal rule
  if (rand() < 0.05) out = out "\n────────────\n\n"
  # ~3% star divider
  if (rand() < 0.03) out = out "★ ★ ★\n\n"

  return out
}
' 2>/dev/null

echo "" >&2
echo "Done." >&2
