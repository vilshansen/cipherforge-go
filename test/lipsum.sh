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

# Parse a human size like 1M, 500K, 2G into bytes.
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
    -s|--size)
      SIZE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/s/^# //p' "$0"; exit 0 ;;
    -*)
      die "unknown flag: $1" ;;
    *)
      # First positional arg that looks like a size, or a filename
      if [[ "$1" =~ ^[0-9]+[KkMmGg]?$ ]]; then
        SIZE="$1"
      elif [[ -z "$OUTFILE" ]]; then
        OUTFILE="$1"
      else
        die "unexpected argument: $1"
      fi
      shift ;;
  esac
done

MAX_BYTES=$(parse_size "$SIZE")

# --- require dictionary -----------------------------------------------------
DICT="/usr/share/dict/words"
[[ -f "$DICT" ]] || die "dictionary not found at $DICT (install words package)"

# --- build word lists -------------------------------------------------------

# Pool A: short common words (2-7 letters, lowercase only) — the backbone.
# We pre-filter once for speed.
echo "Building word lists..." >&2
POOL_A=$(mktemp)
trap 'rm -f "$POOL_A"' EXIT
grep -E '^[a-z]{2,7}$' "$DICT" > "$POOL_A"
A_COUNT=$(wc -l < "$POOL_A")
echo "  ... $(printf "%'d" "$A_COUNT") short words loaded" >&2

# Pool B: proper nouns / capitalized words (for variety in names / places).
POOL_B=$(mktemp)
trap 'rm -f "$POOL_A" "$POOL_B"' EXIT
grep -E '^[A-Z][a-z]{2,9}$' "$DICT" > "$POOL_B"
B_COUNT=$(wc -l < "$POOL_B")
echo "  ... $(printf "%'d" "$B_COUNT") proper nouns loaded" >&2

# --- random picker (fast, no subshell per word) ------------------------------
rand_word() {
  local pool="$1"
  local total="$2"
  local line=$(( (RANDOM * 32768 + RANDOM) % total + 1 ))
  sed -n "${line}p" "$pool"
}

# --- punctuation & UTF-8 decoration -----------------------------------------
# Period-ending punctuation
PERIODS=( "." "." "." "." "." "?" "!" )
# Intra-sentence punctuation (comma, semicolon, colon, em-dash, en-dash)
COMMAS=( "," "," "," "," "," ";" ":" " — " " – " )
# Paired delimiters: we randomly wrap a word/phrase in these
LPAREN=( "("  "["  "{"  "\""  "'"  "«" )
RPAREN=( ")"  "]"  "}"  "\""  "'"  "»" )

# UTF-8 sprinkles: characters / short strings to insert mid-sentence or as
# standalone decoration.  Keep these recognisable so the output still reads
# as "English text with UTF-8 spice" rather than pure noise.
UTF8_SPRINKLES=(
  # typographic
  "“"   # "
  "”"   # "
  "‘"   # '
  "’"   # '
  "—"   # —
  "–"   # –
  "…"   # …
  " "   # NBSP
  # accented / diacritic (common in English loan-words)
  "é"   # é
  "è"   # è
  "ê"   # ê
  "ë"   # ë
  "ñ"   # ñ
  "ü"   # ü
  "ç"   # ç
  "à"   # à
  "â"   # â
  "ä"   # ä
  "ö"   # ö
  "ô"   # ô
  "û"   # û
  "î"   # î
  "ï"   # ï
  # currency
  "€"   # €
  "£"   # £
  "¥"   # ¥
  "¢"   # ¢
  # symbols
  "©"   # ©
  "®"   # ®
  "™"   # ™
  "°"   # °
  "±"   # ±
  "×"   # ×
  "÷"   # ÷
  # math / science
  "∑"   # ∑
  "√"   # √
  "∞"   # ∞
  "≈"   # ≈
  "≠"   # ≠
  "≤"   # ≤
  "≥"   # ≥
  # arrows
  "→"   # →
  "←"   # ←
  "↑"   # ↑
  "↓"   # ↓
  "↔"   # ↔
  # Greek (lowercase, commonly seen in math / science)
  "α"   # α
  "β"   # β
  "γ"   # γ
  "δ"   # δ
  "ε"   # ε
  "λ"   # λ
  "μ"   # μ
  "π"   # π
  "σ"   # σ
  "φ"   # φ
  "ω"   # ω
  # miscellaneous
  "•"   # •
  "★"   # ★
  "☆"   # ☆
  "♥"   # ♥
  "♦"   # ♦
  "♣"   # ♣
  "♠"   # ♠
  "✓"   # ✓
  "✗"   # ✗
)
# Pre-render the sprinkles so printf interprets them once.
declare -a RENDERED_SPRINKLES
for ((i=0; i<${#UTF8_SPRINKLES[@]}; i++)); do
  RENDERED_SPRINKLES[i]=$(printf "${UTF8_SPRINKLES[i]}")
done

# --- UTF-8 sprinkle helpers -------------------------------------------------

# Return a random rendered sprinkle.
rand_sprinkle() {
  local i=$((RANDOM % ${#RENDERED_SPRINKLES[@]}))
  printf '%s' "${RENDERED_SPRINKLES[$i]}"
}

# Insert 0-2 random sprinkles into a string at word boundaries.
sprinkle_text() {
  local text="$1"
  local out="$text"
  local n=$((RANDOM % 3))          # 0, 1, or 2 sprinkles
  local words=( $text )
  local wc=${#words[@]}
  (( wc > 2 )) || { printf '%s' "$text"; return; }

  for ((s=0; s<n; s++)); do
    local pos=$((1 + RANDOM % (wc - 1)))
    local sp="$(rand_sprinkle)"
    local left=() right=()
    for ((j=0; j<wc; j++)); do
      if (( j < pos )); then left+=("${words[j]}")
      else right+=("${words[j]}"); fi
    done
    # Rebuild: left + sprinkle + right
    local rebuilt
    rebuilt="$(printf '%s ' "${left[@]}")$sp$(printf ' %s' "${right[@]}")"
    out="$rebuilt"
    words=( $out )
    wc=${#words[@]}
  done
  printf '%s' "$out"
}

# --- sentence generators ----------------------------------------------------

# Pick a random short word from pool A (cached via sed p-line).
pick_a() { rand_word "$POOL_A" "$A_COUNT"; }
pick_b() { rand_word "$POOL_B" "$B_COUNT"; }

# Build a simple noun phrase: (article) (adjective) NOUN
np() {
  local r=$((RANDOM % 6))
  case $r in
    0) pick_a ;;                                       # bare noun
    1) echo "$(pick_a) $(pick_a)" ;;                   # noun-noun compound
    2) echo "the $(pick_a)" ;;                          # article + noun
    3) echo "the $(pick_a) $(pick_a)" ;;                # article + adj + noun
    4) echo "a $(pick_a)" ;;                            # article + noun
    5) echo "a $(pick_a) $(pick_a)" ;;                  # article + adj + noun
  esac
}

# Build a verb phrase.
vp() {
  local r=$((RANDOM % 5))
  case $r in
    0) pick_a ;;
    1) echo "$(pick_a) $(pick_a)" ;;
    2) echo "$(pick_a) the $(pick_a)" ;;
    3) echo "$(pick_a) a $(pick_a)" ;;
    4) echo "will $(pick_a) the $(pick_a)" ;;
  esac
}

# Build a full sentence.
sentence() {
  local subj vrb obj extra pct
  subj="$(np)"
  vrb="$(vp)"
  # Capitalise first letter of subject
  subj="$(tr '[:lower:]' '[:upper:]' <<< "${subj:0:1}")${subj:1}"

  local s="$subj $vrb"

  # ~40% chance of an object phrase
  if (( RANDOM % 10 < 4 )); then
    obj="$(np)"
    s="$s $obj"
  fi

  # ~30% chance of a prepositional phrase
  if (( RANDOM % 10 < 3 )); then
    local prep
    case $((RANDOM % 8)) in
      0) prep="in"   ;;  1) prep="on"   ;;
      2) prep="at"   ;;  3) prep="with" ;;
      4) prep="from" ;;  5) prep="by"   ;;
      6) prep="for"  ;;  7) prep="under" ;;
    esac
    s="$s $prep the $(pick_a)"
  fi

  # ~10% chance of an extra clause
  if (( RANDOM % 10 < 1 )); then
    local conj
    case $((RANDOM % 3)) in
      0) conj="and"  ;; 1) conj="but"  ;; 2) conj="because" ;;
    esac
    s="$s $conj $(np) $(vp)"
  fi

  # ~15% chance: insert an adverb somewhere
  if (( RANDOM % 10 < 2 )); then
    local adv="$(pick_a)ly"
    s="$adv $s"   # prepend (crude but often works)
  fi

  # ~8% chance: wrap a phrase in paired delimiters
  if (( RANDOM % 100 < 8 )); then
    local di=$((RANDOM % ${#LPAREN[@]}))
    local lparen="${LPAREN[$di]}"
    local rparen="${RPAREN[$di]}"
    # insert after first space
    local first="${s%% *}"
    local rest="${s#* }"
    s="$first $lparen$rest$rparen"
  fi

  # ~5% chance: insert an em-dash parenthetical
  if (( RANDOM % 100 < 5 )); then
    s="$s — $(pick_a) $(pick_a) — $(pick_a)"
  fi

  # ~20% chance: insert an intra-sentence punctuation mark
  if (( RANDOM % 10 < 2 )); then
    local ci=$((RANDOM % ${#COMMAS[@]}))
    local comma="${COMMAS[$ci]}"
    # insert roughly mid-sentence
    local words=( $s )
    local wc=${#words[@]}
    if (( wc > 3 )); then
      local pos=$(( wc / 2 + RANDOM % (wc/2) ))
      local left=()
      local right=()
      for ((i=0; i<wc; i++)); do
        if (( i < pos )); then
          left+=("${words[i]}")
        else
          right+=("${words[i]}")
        fi
      done
      s="$(printf '%s' "${left[@]}")$comma $(printf '%s' "${right[@]}")"
    fi
  fi

  # Sprinkle UTF-8 characters into the sentence body (~40% chance)
  if (( RANDOM % 10 < 4 )); then
    s="$(sprinkle_text "$s")"
  fi

  # Ending punctuation
  s="$s${PERIODS[$((RANDOM % ${#PERIODS[@]}))]} "

  echo "$s"
}

# --- paragraph builder ------------------------------------------------------
paragraph() {
  local n=$(( 2 + RANDOM % 7 ))   # 2-8 sentences
  local out=""
  for ((i=0; i<n; i++)); do
    out+="$(sentence)"
  done
  # ~10% chance of a bullet list or standalone sprinkle line after a paragraph
  if (( RANDOM % 10 < 1 )); then
    out+=$'\n'
    local bullets=$(( 1 + RANDOM % 4 ))
    for ((i=0; i<bullets; i++)); do
      out+=$'  • '"$(np) $(vp) — ${PERIODS[$((RANDOM%${#PERIODS[@]}))]}"$'\n'
    done
  fi
  # ~5% chance of a horizontal-rule-ish line
  if (( RANDOM % 100 < 5 )); then
    out+=$'\n────────────\n\n'
  fi
  # ~3% chance of a ★★★ section divider
  if (( RANDOM % 100 < 3 )); then
    out+="★ ★ ★"$'\n\n'
  fi

  echo -n "$out"
}

# --- main loop ---------------------------------------------------------------
echo "Generating $(numfmt --to=iec "$MAX_BYTES" 2>/dev/null || echo "$MAX_BYTES bytes") of sample text..." >&2

BYTES_WRITTEN=0
PARA_COUNT=0

# --- output destination -----------------------------------------------------
if [[ -n "$OUTFILE" ]]; then
  exec > "$OUTFILE"
fi

while (( BYTES_WRITTEN < MAX_BYTES )); do
  para="$(paragraph)"
  para+=$'\n'   # blank line between paragraphs
  printf '%s' "$para"

  # Count bytes written (printf %s gives us the byte count, not char count).
  BYTES_WRITTEN=$(( BYTES_WRITTEN + ${#para} + 1 ))
  PARA_COUNT=$(( PARA_COUNT + 1 ))

  # Progress to stderr every 100 paragraphs
  if (( PARA_COUNT % 100 == 0 )); then
    printf '  ... %s / %s (%d%%) written\r' \
      "$(numfmt --to=iec "$BYTES_WRITTEN" 2>/dev/null || echo "$BYTES_WRITTEN")" \
      "$(numfmt --to=iec "$MAX_BYTES" 2>/dev/null || echo "$MAX_BYTES")" \
      $(( BYTES_WRITTEN * 100 / MAX_BYTES )) >&2
  fi
done

echo "" >&2
echo "Done — $(printf "%'d" "$BYTES_WRITTEN") bytes in $(printf "%'d" "$PARA_COUNT") paragraphs." >&2
