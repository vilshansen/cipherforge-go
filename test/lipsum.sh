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
} | LC_ALL=C gawk -v MAX_BYTES="$MAX_BYTES" '
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
  # Each entry: "lo,hi,weight" — weight controls selection probability
  # independent of span size.  Large blocks (CJK) get capped weight so
  # smaller blocks (Greek, currency, emoji…) get proportional share.
  split("", rlo); split("", rhi); split("", rw)
  rc = 0; total_weight = 0

  # Block                       | Span    | Weight | Rationale
  # --- BMP / Plane 0 ----------+---------+--------+-------------------
  add_weighted(0x00A0, 0x024F,    8)  # Latin-1 supp + Latin Ext-A/B
  add_weighted(0x0250, 0x02AF,    2)  # IPA Extensions
  add_weighted(0x0370, 0x03FF,    3)  # Greek & Coptic
  add_weighted(0x0400, 0x04FF,    3)  # Cyrillic
  add_weighted(0x0530, 0x058F,    2)  # Armenian
  add_weighted(0x0590, 0x05FF,    2)  # Hebrew
  add_weighted(0x0600, 0x06FF,    3)  # Arabic
  add_weighted(0x0900, 0x0DFF,    3)  # Devanagari through Malayalam
  add_weighted(0x0E00, 0x0FFF,    2)  # Thai, Lao, Tibetan
  add_weighted(0x2000, 0x206F,    3)  # General punctuation
  add_weighted(0x2070, 0x209F,    1)  # Superscripts & subscripts
  add_weighted(0x20A0, 0x20CF,    2)  # Currency symbols
  add_weighted(0x2100, 0x214F,    2)  # Letterlike symbols
  add_weighted(0x2150, 0x218F,    1)  # Number forms
  add_weighted(0x2190, 0x21FF,    3)  # Arrows
  add_weighted(0x2200, 0x22FF,    4)  # Mathematical operators
  add_weighted(0x2300, 0x23FF,    2)  # Miscellaneous technical
  add_weighted(0x2460, 0x24FF,    1)  # Enclosed alphanumerics
  add_weighted(0x2500, 0x257F,    2)  # Box drawing
  add_weighted(0x2580, 0x259F,    1)  # Block elements
  add_weighted(0x25A0, 0x25FF,    2)  # Geometric shapes
  add_weighted(0x2600, 0x26FF,    3)  # Miscellaneous symbols
  add_weighted(0x2700, 0x27BF,    2)  # Dingbats
  add_weighted(0x2800, 0x28FF,    1)  # Braille patterns
  add_weighted(0x3000, 0x303F,    1)  # CJK symbols & punctuation
  add_weighted(0x3040, 0x30FF,    2)  # Hiragana & Katakana
  add_weighted(0x3400, 0x4DBF,    2)  # CJK Ext A (sample)
  add_weighted(0x4E00, 0x9FFF,    5)  # CJK Unified Ideographs
  add_weighted(0xAC00, 0xD7AF,    3)  # Hangul syllables
  add_weighted(0xF900, 0xFAFF,    1)  # CJK compat ideographs
  add_weighted(0xFB00, 0xFB4F,    1)  # Alphabetic presentation forms
  add_weighted(0xFE30, 0xFE4F,    1)  # CJK compatibility forms
  add_weighted(0xFF00, 0xFFEF,    2)  # Halfwidth & fullwidth forms

  # --- SMP / Plane 1 ----------+---------+--------+-------------------
  add_weighted(0x10300, 0x1032F,  1)  # Old Italic
  add_weighted(0x10380, 0x1039F,  1)  # Ugaritic
  add_weighted(0x12000, 0x123FF,  1)  # Cuneiform
  add_weighted(0x1D000, 0x1D0FF,  1)  # Byzantine musical symbols
  add_weighted(0x1D100, 0x1D1FF,  1)  # Musical symbols
  add_weighted(0x1D400, 0x1D7FF,  3)  # Mathematical alphanumerics
  add_weighted(0x1F000, 0x1F02F,  1)  # Mahjong tiles
  add_weighted(0x1F0A0, 0x1F0FF,  1)  # Playing cards
  add_weighted(0x1F300, 0x1F5FF,  3)  # Misc symbols & pictographs
  add_weighted(0x1F600, 0x1F64F,  2)  # Emoticons (emoji)
  add_weighted(0x1F680, 0x1F6FF,  2)  # Transport & map symbols
  add_weighted(0x1F780, 0x1F7FF,  1)  # Geometric shapes extended
  add_weighted(0x1F900, 0x1F9FF,  2)  # Supplemental symbols & pictographs
  add_weighted(0x1FA00, 0x1FA6F,  1)  # Chess symbols

  # --- SIP / Plane 2 ----------+---------+--------+-------------------
  add_weighted(0x20000, 0x2A6DF,  3)  # CJK Ext B
  add_weighted(0x2F800, 0x2FA1F,  1)  # CJK compat ideographs supp

  # --- TIP / Plane 3 ----------+---------+--------+-------------------
  add_weighted(0x30000, 0x3134F,  1)  # CJK Ext G

  # --- SSP / Plane 14 ---------+---------+--------+-------------------
  add_weighted(0xE0000, 0xE007F,  1)  # Tags

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
function add_weighted(lo, hi, w) {
  rc++
  rlo[rc] = lo; rhi[rc] = hi; rw[rc] = w
  total_weight += w
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

# Pick a random code point: first select a range by weight, then
# pick uniformly within its span.  Skips noncharacters.
function random_codepoint(   pos, i, lo, hi, span, cp) {
  pos = int(rand() * total_weight)
  for (i = 1; i <= rc; i++) {
    if (pos < rw[i]) {
      lo = rlo[i] + 0
      hi = rhi[i] + 0
      span = hi - lo + 1
      cp = lo + int(rand() * span)
      # Skip noncharacters: U+FDD0-U+FDEF and U+xxFFFE-U+xxFFFF
      if ((cp >= 0xFDD0 && cp <= 0xFDEF) || (cp % 0x10000) >= 0xFFFE) {
        return random_codepoint()
      }
      return cp
    }
    pos -= rw[i]
  }
  return 0xFFFD
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
