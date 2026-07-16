import std/[unicode, strutils]

proc isWideRune(r: Rune): bool =
  let cp = r.ord
  if (cp >= 0x1100 and cp <= 0x115F) or
     (cp >= 0x2E80 and cp <= 0x303E) or
     (cp >= 0x3041 and cp <= 0x33FF) or
     (cp >= 0x3400 and cp <= 0x4DBF) or
     (cp >= 0x4E00 and cp <= 0x9FFF) or
     (cp >= 0xF900 and cp <= 0xFAFF) or
     (cp >= 0xFF00 and cp <= 0xFF60) or
     (cp >= 0xFFE0 and cp <= 0xFFE6) or
     (cp >= 0x20000 and cp <= 0x3FFFD):
    return true
  return false

proc runeWidth(r: Rune): int =
  result = if isWideRune(r): 2 else: 1

proc displayWidth(text: string): int =
  result = 0
  for r in text.toRunes: result += runeWidth(r)

proc wrapText(text: string, maxWidth: int): seq[string] =
  result = @[]
  if text == "": return @[""]
  if maxWidth < 1: return @[""]
  var currentLine = ""
  var currentWidth = 0
  for r in text.toRunes:
    let w = if r.ord < 128: 1 else: 2
    if currentWidth + w > maxWidth and currentLine.len > 0:
      result.add(currentLine)
      currentLine = $r
      currentWidth = w
    else:
      currentLine.add($r)
      currentWidth += w
  if currentLine.len > 0:
    result.add(currentLine)

proc main() =
  let maxW = 18
  let text = "あいうえおかきくけこさしすせそたちつてとなにぬねの"
  let lines = wrapText(text, maxW)
  echo "nlines=", lines.len
  for i, l in lines:
    echo "line ", i, " dispWidth=", displayWidth(l), " (maxW=", maxW, ") ok=", displayWidth(l) <= maxW, " [", l, "]"
  let text2 = "a".repeat(40)
  let lines2 = wrapText(text2, 10)
  for i, l in lines2:
    echo "ascii line ", i, " len=", l.len, " ok=", l.len <= 10

main()
