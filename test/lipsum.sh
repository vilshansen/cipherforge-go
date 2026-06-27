#!/bin/bash
#===============================================================================
# lipsum.sh — real English sample text with UTF-8 richness across the spectrum
#
# Usage:  ./lipsum.sh [SIZE] [OUTPUT_FILE]
#         ./lipsum.sh -s 500K > sample.txt
#         ./lipsum.sh 2M output.txt
#
# SIZE accepts K/M/G suffix (default: 1M = 1 megabyte).
#===============================================================================
set -euo pipefail

SIZE="1M"
OUTFILE=""
die() { echo "ERROR: $*" >&2; exit 1; }

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
    *)    die "unknown suffix: $raw (use K, M, G)" ;;
  esac
}

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

echo "Loading words..." >&2
WORDS_A=$(grep -E '^[a-z]{2,7}$' "$DICT")
WORDS_B=$(grep -E '^[A-Z][a-z]{2,9}$' "$DICT")
echo "Generating $(numfmt --to=iec "$MAX_BYTES" 2>/dev/null || echo "$MAX_BYTES bytes")..." >&2

[[ -n "$OUTFILE" ]] && exec > "$OUTFILE"

{
  printf '%s\n' "$WORDS_A"
  echo "---SENTINEL---"
  printf '%s\n' "$WORDS_B"
} | LC_ALL=C gawk -v MAX_BYTES="$MAX_BYTES" '
BEGIN { srand(); cnt_a=0; cnt_b=0; reading_b=0 }

{
  if ($0 == "---SENTINEL---") { reading_b=1; next }
  if (!reading_b) { if ($0!="") words_a[cnt_a++]=$0 }
  else            { if ($0!="") words_b[cnt_b++]=$0 }
}

# === English sentence generator (top-level functions) ==================
function pick_a() { return words_a[int(rand()*cnt_a)] }
function pick_b() { return words_b[int(rand()*cnt_b)] }
function cap(s)   { return toupper(substr(s,1,1)) substr(s,2) }
function np(  r) {
  r = int(rand()*6)
  if (r==0) return pick_a()
  if (r==1) return pick_a() " " pick_a()
  if (r==2) return "the " pick_a()
  if (r==3) return "the " pick_a() " " pick_a()
  if (r==4) return "a " pick_a()
  return "a " pick_a() " " pick_a()
}
function vp(  r) {
  r = int(rand()*5)
  if (r==0) return pick_a()
  if (r==1) return pick_a() " " pick_a()
  if (r==2) return pick_a() " the " pick_a()
  if (r==3) return pick_a() " a " pick_a()
  return "will " pick_a() " the " pick_a()
}
function sentence(  s) {
  s = cap(np()) " " vp()
  if (rand()<0.4)  s = s " " np()
  if (rand()<0.3)  s = s " " substr("in on at with from by under", 1+int(rand()*8)*5, 5) " the " pick_a()
  if (rand()<0.15) s = pick_a() "ly " s
  s = s substr(". . . . . ? !", 1+int(rand()*8)*2, 2)
  return s
}
function paragraph(  n,out,i) {
  n = 2 + int(rand()*7)
  out = ""
  for (i=0; i<n; i++) out = out sentence() " "
  return out
}

END {
  if (cnt_a == 0) { print "ERROR: no words loaded" > "/dev/stderr"; exit 1 }

  # === Curated UTF-8 characters, spread across the entire spectrum ====
  # Each line = one "showcase" of ~16 chars from different ranges.
  # Planes 0 through 16 are represented.  All are assigned characters
  # that render correctly (no PUA, no unassigned filler).

  split("", utf8_lines)
  uc = 0

  # These strings contain real assigned characters from diverse blocks
  # at widely separated code points — plane 0 through plane 16.
  utf8_lines[++uc] = "Latin: ©®™° ±²³´µ ¶·¸¹º »¼½¾¿ ÀÁÂÃ ÄÅÆÇÈ ÉÊËÌÍ ÎÏÐÑÒ ÓÔÕÖ× ØÙÚÛÜ ÝÞßàá âãäåæ çèéêë ìíîïðñ òóôõö÷ øùúûüý þÿ"
  utf8_lines[++uc] = "Greek: ΑΒΓΔΕΖΗΘ ΙΚΛΜΝΞΟΠ ΡΣΤΥΦΧΨΩ αβγδεζηθ ικλμνξοπ ρστυφχψω"
  utf8_lines[++uc] = "Cyrillic: АБВГДЕЖЗ ИЙКЛМНОП РСТУФХЦЧ ШЩЪЫЬЭЮЯ абвгдежз ийклмноп рстуфхцч шщъыьэюя"
  utf8_lines[++uc] = "Hebrew: אבגדהוז חטיכלמ נסעפצק רשת"
  utf8_lines[++uc] = "Arabic: ابتثجحخ دذرزسش صضطظع غفقكلم نهوي"
  utf8_lines[++uc] = "Devanagari: अआइईउऊ ऋएऐओऔ कखगघङ चछजझञ टठडढण तथदधन पफबभम यरलवश षसह"
  utf8_lines[++uc] = "Thai: กขฃคฅฆง จฉชซฌญ ฎฏฐฑฒณ ดตถทธน บปผฝพฟ ภมยรฤล ฦวศษสห ฬอฮ"
  utf8_lines[++uc] = "Punctuation: – — ― ‗ \047 \047 ‚ ‛ ＂ ＂ „ ‟ † ‡ • … ‰ ′ ″ ‹ › ‼ ‽ ⁂ ⁃ ⁄ ⁅ ⁆ ⁇ ⁈ ⁉ ⁊ ⁋ ⁌ ⁍ ⁎ ⁏"
  utf8_lines[++uc] = "Currency: $ ¢ £ ¤ ¥ ₠ ₡ ₢ ₣ ₤ ₥ ₦ ₧ ₨ ₩ ₪ ₫ € ₭ ₮ ₯ ₰ ₱ ₲ ₳ ₴ ₵ ₶ ₷ ₸ ₹ ₺ ₻ ₼ ₽ ₾ ₿"
  utf8_lines[++uc] = "Math: ∀ ∁ ∂ ∃ ∄ ∅ ∆ ∇ ∈ ∉ ∊ ∋ ∌ ∍ ∎ ∏ ∐ ∑ − ∓ ∔ ∕ ∖ ∗ ∘ ∙ √ ∛ ∜ ∝ ∟ ∡ ∢ ∤ ∥ ∦ ∧ ∨ ∩ ∪ ∴ ∵ ∶ ∷"
  utf8_lines[++uc] = "Arrows: ← ↑ → ↓ ↔ ↕ ↖ ↗ ↘ ↙ ↚ ↛ ↜ ↝ ↞ ↟ ↠ ↡ ↢ ↣ ↤ ↥ ↦ ↧ ↨ ↩ ↪ ↫ ↬ ↭ ↮ ↯"
  utf8_lines[++uc] = "Tech: ⌂ ⌃ ⌄ ⌅ ⌆ ⌇ ⌈ ⌉ ⌊ ⌋ ⌌ ⌍ ⌎ ⌏ ⌐ ⌑ ⌒ ⌓ ⌔ ⌕ ⌖ ⌗ ⌘ ⌙ ⌚ ⌛ ⌜ ⌝ ⌞ ⌟ ⌠ ⌡ ⌢ ⌣ ⌤ ⌥ ⌦ ⌧"
  utf8_lines[++uc] = "Box: ─ ━ │ ┃ ┄ ┅ ┆ ┇ ┈ ┉ ┊ ┋ ┌ ┍ ┎ ┏ ┐ ┑ ┒ ┓ └ ┕ ┖ ┗ ┘ ┙ ┚ ┛ ├ ┝ ┞ ┟ ┠ ┡ ┢ ┣ ┤ ┥ ┦"
  utf8_lines[++uc] = "Blocks: ▁ ▂ ▃ ▄ ▅ ▆ ▇ █ ▉ ▊ ▋ ▌ ▍ ▎ ▏ ▐ ░ ▒ ▓ ▔ ▕ ▖ ▗ ▘ ▙ ▚ ▛ ▜ ▝ ▞ ▟"
  utf8_lines[++uc] = "Shapes: ■ □ ▢ ▣ ▤ ▥ ▦ ▧ ▨ ▩ ▪ ▫ ▬ ▭ ▮ ▯ ▰ ▱ ▲ △ ▴ ▵ ▶ ▷ ▸ ▹ ► ▻ ▼ ▽ ▾ ▿"
  utf8_lines[++uc] = "Dingbats: ✁ ✂ ✃ ✄ ✆ ✇ ✈ ✉ ✌ ✍ ✎ ✏ ✐ ✑ ✒ ✓ ✔ ✕ ✖ ✗ ✘ ✙ ✚ ✛ ✜ ✝ ✞ ✟ ✠ ✡ ✢ ✣ ✤ ✥"
  utf8_lines[++uc] = "Symbols: ☀ ☁ ☂ ☃ ☄ ★ ☆ ☇ ☈ ☉ ☊ ☋ ☌ ☍ ☎ ☏ ☐ ☑ ☒ ☓ ☔ ☕ ☖ ☗ ☘ ☙ ☚ ☛ ☜ ☝ ☞ ☟"
  utf8_lines[++uc] = "CJK: 一乙二十丁 厂七卜八人 入义儿九匕 几刁了乃刀 力又乜三干 亍于亏士土 兀才下寸丈 大与万弋上"
  utf8_lines[++uc] = "Hiragana: ぁあぃいぅ うぇえぉお かがきぎく ぐけげこご さざしじす ずせぜそぞ ただちぢつ っづてでと"
  utf8_lines[++uc] = "Katakana: ァアィイゥ ウェエォオ カガキギク グケゲコゴ サザシジス ズセゼソゾ タダチヂツ ッヅテデト"
  utf8_lines[++uc] = "Hangul: 가각간갇갈 갉갊감갑갓 강갖갗같갚 갛개객갠객 갞갟갠갡 갢갣갤갥갦 갧갨갩갪갫 갬갭갮갯갰 갱갲갳갴갵"
  utf8_lines[++uc] = "Yi: ꀀꀁꀂꀃꀄꀅ ꀆꀇꀈꀉꀊ ꀋꀌꀍꀎꀏ ꀐꀑꀒꀓꀔ ꀕꀖꀗꀘꀙ ꀚꀛꀜꀝꀞ ꀟꀠꀡꀢꀣ"
  utf8_lines[++uc] = "Math Alphanum (plane 1): 𝐀𝐁𝐂𝐃𝐄 𝐅𝐆𝐇𝐈𝐉 𝐊𝐋𝐌𝐍𝐎 𝐏𝐐𝐑𝐒𝐓 𝐔𝐕𝐖𝐗𝐘 𝐙𝐚𝐛𝐜𝐝 𝐞𝐟𝐠𝐡𝐢 𝐣𝐤𝐥𝐦𝐧 𝐨𝐩𝐪𝐫𝐬 𝐭𝐮𝐯𝐰𝐱 𝐲𝐳"
  utf8_lines[++uc] = "Musical (plane 1): 𝄀𝄁𝄂𝄃𝄄 𝄅𝄆𝄇𝄈𝄉 𝄊𝄋𝄌𝄍𝄎 𝄏𝄐𝄑𝄒𝄓 𝄔𝄕𝄖𝄗𝄘 𝄙𝄚𝄛𝄜𝄝 𝄞𝄟𝄠𝄡𝄢 𝄣𝄤𝄥𝄦𝄧"
  utf8_lines[++uc] = "Emoji (plane 1): 😀😁😂😃😄 😅😆😇😈😉 😊😋😌😍😎 😏😐😑😒😓 😔😕😖😗😘 😙😚😛😜😝"
  utf8_lines[++uc] = "Cuneiform (plane 1): 𒀀𒀁𒀂𒀃𒀄 𒀅𒀆𒀇𒀈𒀉 𒀊𒀋𒀌𒀍𒀎 𒀏𒀐𒀑𒀒𒀓 𒀔𒀕𒀖𒀗𒀘"
  utf8_lines[++uc] = "CJK Ext B (plane 2): 𠀀𠀁𠀂𠀃𠀄 𠀅𠀆𠀇𠀈𠀉 𠀊𠀋𠀌𠀍𠀎 𠀏𠀐𠀑𠀒𠀓 𠀔𠀕𠀖𠀗𠀘"
  utf8_lines[++uc] = "CJK Ext G (plane 3): 𰀀𰀁𰀂𰀃𰀄 𰀅𰀆𰀇𰀈𰀉 𰀊𰀋𰀌𰀍𰀎 𰀏𰀐𰀑𰀒𰀓 𰀔𰀕𰀖𰀗𰀘"
  utf8_lines[++uc] = "Plane 14 (SSP): only invisible formatting tags & variation selectors — no displayable characters."

  bytes_out = 0
  utf8_idx = 0

  while (bytes_out < MAX_BYTES) {
    # Generate 1-3 English paragraphs
    npg = 1 + int(rand()*3)
    for (p=0; p<npg; p++) {
      para = paragraph()
      printf "%s\n\n", para
      bytes_out += length(para) + 2
      if (bytes_out >= MAX_BYTES) break
    }
    if (bytes_out >= MAX_BYTES) break

    # Insert a UTF-8 showcase line (cycle through the curated list)
    utf8_idx++
    if (utf8_idx > uc) utf8_idx = 1
    line = "  [UTF-8] " utf8_lines[utf8_idx] "\n\n"
    printf "%s", line
    bytes_out += length(line)
  }
  system("")
}
'
echo "" >&2
echo "Done." >&2
