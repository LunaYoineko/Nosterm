import std/[asyncdispatch, json, strformat, os, strutils, times, tables, unicode, random]
import std/terminal
from posix import poll, read, TPollFd
import ws, illwill
import secp256k1
import nimSHA2

# =============================================================================
# Nosterm - Nostr TUI Client in Nim
# =============================================================================
# Main features:
# - Relay (wss://yabu.me) subscription for Kind 0 (profile) and Kind 1 (notes)
# - Timeline display with Japanese auto-wrap
# - nsec (Bech32 secret key) input/save/load
# - secp256k1 Schnorr signature for posting
# - illwill library for cross-platform TUI rendering
# =============================================================================

# --------------------------------------------------
# Display width utility (ASCII=1, wide=2)
# --------------------------------------------------
# A full-width (East Asian Wide) rune occupies 2 terminal columns. Box-drawing
# and other non-CJK symbols (ord >= 128) are single-width and must NOT be
# treated as wide, otherwise the renderer would skip a column.
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
  for r in text.toRunes:
    result += runeWidth(r)

# Truncate `s` so its display width does not exceed `maxW` (keeps ASCII simple).
proc fitToWidth(s: string, maxW: int): string =
  if displayWidth(s) <= maxW: return s
  if maxW <= 1: return ""
  var res = ""
  var w = 0
  for r in s.toRunes:
    let cw = runeWidth(r)
    if w + cw > maxW - 1: break
    res.add(r)
    w += cw
  res.add("…")
  return res

# Write string at (x,y) with proper full-width handling.
# illwill 0.4.1 has no wide-char support: each buffer cell maps to one
# terminal column. A full-width char occupies 2 columns, so for it we write
# the rune to cell cx and a NUL placeholder to cx+1 (the renderer skips the
# placeholder when emitting the glyph).
proc writeLine(tb: var TerminalBuffer, x, y: int, text: string, color: illwill.ForegroundColor) =
  if y < 0 or y >= tb.height: return
  var cx = x
  for r in text.toRunes:
    if isWideRune(r):
      if cx + 1 >= tb.width - 1: break   # protect right border
      tb[cx, y] = TerminalChar(ch: r, fg: color, bg: bgNone, style: {})
      tb[cx + 1, y] = TerminalChar(ch: Rune(0), fg: color, bg: bgNone, style: {})
      cx += 2
    else:
      if cx >= tb.width - 1: break        # stop at right border
      tb[cx, y] = TerminalChar(ch: r, fg: color, bg: bgNone, style: {})
      cx += 1
  # Pad the remainder of the line with spaces so stale cells are cleared.
  while cx < tb.width - 1:
    tb[cx, y] = TerminalChar(ch: Rune(32), fg: color, bg: bgNone, style: {})
    cx += 1

# --------------------------------------------------
# Custom wide-char-aware renderer.
# illwill's own display() assumes 1 cell == 1 terminal column, which breaks
# for full-width (2-column) runes and forces a full-screen redraw every frame
# (flicker). Instead we emit each row as one ANSI line and only rewrite rows
# whose content actually changed.
# --------------------------------------------------
var prevScreen: seq[string] = @[]
var forceRedraw = false   # when set, the next render repaints every row

proc sgrFor(fg: illwill.ForegroundColor, bg: illwill.BackgroundColor,
            style: set[illwill.Style]): string =
  var parts: seq[string] = @[]
  let f = fg.int
  if f == 0: parts.add("39")
  elif f >= 30 and f <= 37:
    if illwill.styleBright in style: parts.add($(f - 30 + 90))
    else: parts.add($(f))
  let b = bg.int
  if b == 0: parts.add("49")
  elif b >= 40 and b <= 47:
    if illwill.styleBright in style: parts.add($(b - 40 + 100))
    else: parts.add($(b))
  if illwill.styleBright in style and parts.len == 0: parts.add("1")
  if parts.len == 0: return "\e[0m"
  result = "\e[" & parts.join(";") & "m"

proc renderToTerminal(tb: var TerminalBuffer) =
  let H = tb.height
  let W = tb.width
  if forceRedraw:
    prevScreen = newSeq[string](H)
    forceRedraw = false
  if prevScreen.len != H:
    prevScreen = newSeq[string](H)
  for y in 0 ..< H:
    var line = ""
    var curSgr = "\e[0m"
    var curText = ""
    var x = 0
    while x < W:
      let c = tb[x, y]
      if isWideRune(c.ch):
        let s = sgrFor(c.fg, c.bg, c.style)
        if s != curSgr:
          if curText.len > 0: line &= curSgr & curText
          curSgr = s
          curText = ""
        curText &= $c.ch
        x += 2
        continue
      # A NUL placeholder belongs to a wide char we just skipped; ignore it.
      if c.ch.ord == 0:
        x += 1
        continue
      let s = sgrFor(c.fg, c.bg, c.style)
      if s != curSgr:
        if curText.len > 0: line &= curSgr & curText
        curSgr = s
        curText = ""
      curText &= $c.ch
      x += 1
    if curText.len > 0: line &= curSgr & curText
    line &= "\e[0m"
    if y >= prevScreen.len or prevScreen[y] != line:
      stdout.write("\e[" & $(y + 1) & ";1H" & line)
      prevScreen[y] = line
  flushFile(stdout)

proc setTermCursor(x, y: int) =   # x, y are 0-based
  stdout.write("\e[" & $(y + 1) & ";" & $(x + 1) & "H")
  flushFile(stdout)

proc showTermCursor() =
  stdout.write("\e[?25h")
  flushFile(stdout)

proc hideTermCursor() =
  stdout.write("\e[?25l")
  flushFile(stdout)

# --------------------------------------------------
# Japanese filter helper
# --------------------------------------------------
proc containsJapanese(text: string): bool =
  for r in text.toRunes:
    let cp = r.ord
    if (cp >= 0x3040 and cp <= 0x309F) or
       (cp >= 0x30A0 and cp <= 0x30FF) or
       (cp >= 0x4E00 and cp <= 0x9FAF) or
       (cp >= 0xFF00 and cp <= 0xFFEF):
      return true
  return false

# --------------------------------------------------
# Auto-wrap (pure content, no indent)
# --------------------------------------------------
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

# --------------------------------------------------
# Bech32 (nsec / npub) decode + encode - pure Nim implementation
# --------------------------------------------------
const Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

proc bech32DecodeBytes(bech: string): seq[byte] =
  let idx = bech.find('1')
  if idx < 0: return @[]
  let dataPart = bech[idx + 1 .. ^1]
  var bytes5: seq[byte] = @[]
  for c in dataPart:
    let i = Bech32Charset.find(c)
    if i == -1: return @[]
    bytes5.add(i.byte)
  if bytes5.len < 6: return @[]
  bytes5.setLen(bytes5.len - 6)
  var out8: seq[byte] = @[]
  var acc = 0'u32
  var bits = 0
  for b in bytes5:
    acc = (acc shl 5) or b.uint32
    bits += 5
    while bits >= 8:
      bits -= 8
      out8.add(((acc shr bits) and 0xFF'u32).byte)
  result = out8

proc decodeBech32(bechString: string): string =
  if not bechString.startsWith("nsec1"): return ""
  let b = bech32DecodeBytes(bechString)
  if b.len != 32: return ""
  result = ""
  for x in b: result.add(x.toHex(2).toLowerAscii())

proc decodeNpubToHex(npub: string): string =
  if not npub.startsWith("npub1"): return ""
  let b = bech32DecodeBytes(npub)
  if b.len != 32: return ""
  result = ""
  for x in b: result.add(x.toHex(2).toLowerAscii())

proc hexToBytes(s: string): seq[byte] =
  result = @[]
  var i = 0
  while i + 1 < s.len:
    result.add(parseHexInt(s[i .. i + 1]).byte)
    i += 2

proc bech32Polymod(values: seq[int]): int64 =
  let GEN = [0x3b6a57b2'i64, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  result = 1'i64
  for v in values:
    let b = result shr 25
    result = ((result and 0x1ffffff) shl 5) xor v.int64
    for i in 0 .. 4:
      if ((b shr i) and 1) == 1:
        result = result xor GEN[i]

proc encodeBech32(hrp: string, dataBytes: seq[byte]): string =
  # 8-bit -> 5-bit groups
  var acc = 0
  var bits = 0
  var data5: seq[int] = @[]
  for b in dataBytes:
    acc = (acc shl 8) or b.int
    bits += 8
    while bits >= 5:
      bits -= 5
      data5.add((acc shr bits) and 31)
  if bits > 0:
    data5.add((acc shl (5 - bits)) and 31)
  # values for checksum (hrp expanded + data)
  var values: seq[int] = @[]
  for c in hrp: values.add(ord(c) shr 5)
  values.add(0)
  for c in hrp: values.add(ord(c) and 31)
  for d in data5: values.add(d)
  for i in 0 .. 5: values.add(0)
  let chk = bech32Polymod(values) xor 1
  for i in 0 .. 5:
    data5.add((chk shr (5 * (5 - i))) and 31)
  result = hrp & "1"
  for d in data5:
    result.add(Bech32Charset[d])

# --------------------------------------------------
# 1. Type definitions and global state
# --------------------------------------------------
type
  NostrEvent = object
    id: string        # Event ID (for deduplication)
    pubkey: string    # Public key (hex, 64 chars)
    content: string   # Note content
    createdAt: int64  # Creation timestamp (Unix time, for sorting)
    client: string    # Client name from the ["client", name] tag ("" if none)

  AppMode = enum
    ModeNormal,   # Browse/scroll mode
    ModeInput,    # Post input mode
    ModeKeyInput, # nsec input mode
    ModeMention,  # Mention picker mode
    ModeRelay,    # Relay manager
    ModeRelayAdd, # Adding a relay (URL input)
    ModeRelayPick, # Picking relays from the account's kind 10002 list
    ModeReaction,  # Reaction emoji input mode
    ModeSettings    # Standalone settings window (relays, key, filters)

var timeline: seq[NostrEvent] = @[]
var profileCache = initTable[string, string]()  # pubkey(lowercase) -> display name
# Reactions (NIP-25): event id -> list of (emoji, reactor pubkey).
var reactions = initTable[string, seq[tuple[emoji: string, pubkey: string]]]()
var selectedEventId = ""   # currently focused post (for reacting); "" = newest
var reactionBuffer = ""    # emoji being typed in ModeReaction
var settingsActive = false  # true when relay/key sub-modes were opened from Settings
var needsRedraw = true
var scrollOffset = 0

var appMode = AppMode.ModeNormal
var inputBuffer = ""
var keyInputBuffer = ""
var savedSecKeyHex = ""
var myPubkeyHex = ""
var savedNsec = ""
let configPath = getHomeDir() / ".nosterm_config"
var pendingProfiles: seq[string] = @[]
var japaneseOnly = false

# Terminal size (globals so input handlers can clamp to the line width)
var cols = 80
var rows = 24

# Mention state
var mentionMap = initTable[string, string]()            # displayName -> pubkeyHex (current draft)
var mentionList: seq[tuple[name: string, pubkey: string]] = @[]
var mentionSel = 0
var mentionAnchor = -1   # index in inputBuffer of the '@' that opened the picker

# Pending UTF-8 bytes read directly from stdin (bypassing illwill's
# single-byte key reader) so Japanese / multi-byte input is captured correctly.
var pendingInput: seq[byte] = @[]

# Sentinel runes returned by the raw reader for arrow keys (never rendered).
const RuneUp*    = Rune(0xEE01)
const RuneDown*  = Rune(0xEE02)
const RuneLeft*  = Rune(0xEE03)
const RuneRight* = Rune(0xEE04)

# --------------------------------------------------
# Relay configuration + live connections
# --------------------------------------------------
type
  RelayConfig = object
    url: string
    read: bool
    write: bool
  RelayConn = object
    url: string
    read: bool
    write: bool
    ws: WebSocket
    gen: int

var relayConfigs: seq[RelayConfig] = @[]   # persisted relay settings
var relayConns: seq[RelayConn] = @[]       # active connections (for sending)
var relayGen = 0                           # bumps on every config (re)apply
var relaySel = 0                           # selected relay in the manager
var relayAddBuffer = ""                    # text typed when adding a relay
var accountRelays: seq[tuple[url: string, read: bool, write: bool]] = @[]  # candidates from kind 10002
var fetchingAccountRelays = false
var relayPickSel = 0                        # selected candidate in pick screen

# --------------------------------------------------
# Cleanup procedure
# --------------------------------------------------
proc exitProc() {.noconv.} =
  illwillDeinit()
  showTermCursor()
  quit(0)

# --------------------------------------------------
# 2. Config file read/write (JSON: nsec + relays)
# --------------------------------------------------
proc saveConfig() =
  try:
    var j = %*{}
    j["nsec"] = %* savedNsec
    var relaysJson = newJArray()
    for rc in relayConfigs:
      var r = %*{}
      r["url"] = %* rc.url
      r["read"] = %* rc.read
      r["write"] = %* rc.write
      relaysJson.add(r)
    j["relays"] = relaysJson
    writeFile(configPath, $j)
    discard execShellCmd("chmod 600 " & quoteShell(configPath))
  except CatchableError:
    discard

proc loadConfig(): bool =
  result = false
  if fileExists(configPath):
    let txt = readFile(configPath).strip()
    if txt.startsWith("{"):
      try:
        let j = parseJson(txt)
        if j.hasKey("nsec"):
          let ns = j["nsec"].getStr()
          let hex = decodeBech32(ns)
          if hex != "":
            savedNsec = ns
            savedSecKeyHex = hex
            result = true
        if j.hasKey("relays"):
          for r in j["relays"]:
            relayConfigs.add(RelayConfig(
              url: r["url"].getStr(),
              read: if r.hasKey("read"): r["read"].getBool() else: true,
              write: if r.hasKey("write"): r["write"].getBool() else: true))
      except CatchableError:
        discard
    elif txt.startsWith("nsec1"):
      # Migrate legacy single-nsec config.
      let hex = decodeBech32(txt)
      if hex != "":
        savedNsec = txt
        savedSecKeyHex = hex
        result = true
  if relayConfigs.len == 0:
    relayConfigs.add(RelayConfig(url: "wss://yabu.me", read: true, write: true))

# Apply a freshly typed nsec: decode, store, persist.
proc applyNsec(nsec: string): bool =
  let hex = decodeBech32(nsec)
  if hex == "":
    return false
  savedNsec = nsec
  savedSecKeyHex = hex
  # Derive our own pubkey so we can fetch the account's relay list (kind 10002).
  let skRes = SkSecretKey.fromHex(savedSecKeyHex)
  if skRes.isOk:
    myPubkeyHex = $skRes.value.toPublicKey().toXOnly()
  saveConfig()
  return true

# --------------------------------------------------
# 3. Nostr post sending (Schnorr signature)
# --------------------------------------------------
proc insertEvent(ev: NostrEvent)   # forward declaration (defined after fetchProfiles)
proc sendToRelays(msg: string) {.async.}
proc applyRelayConfig()
proc collectAccountRelay(content: string)
proc refreshMentionFilter()
proc refetchTimeline()
proc sendReaction(targetId, targetAuthor, emoji: string) {.async.}
proc moveSelection(delta: int)
proc currentSelectedEvent(): NostrEvent

proc sendNostrPost(content: string, mentions: seq[string] = @[]) {.async.} =
  if savedSecKeyHex == "": return

  let seckeyRes = SkSecretKey.fromHex(savedSecKeyHex)
  if not seckeyRes.isOk: return
  let seckey = seckeyRes.value
  
  let pubkey = seckey.toPublicKey()
  let xonly = pubkey.toXOnly()
  let pubkeyHex = $xonly

  let createdAt = getTime().toUnix()
  let tags = newJArray()
  tags.add(%* ["client", "Nosterm"])
  # Nostr mentions: one ["p", "<pubkey hex>"] tag per mentioned user.
  for m in mentions:
    tags.add(%* ["p", m])
  
  let serializeArray = %*[
    0, pubkeyHex, createdAt, 1, tags, content
  ]
  
  let hashData = computeSHA256($serializeArray)
  # Nostr ids/sigs MUST be lowercase hex; relays compare the id case-sensitively
  # against the recomputed hash, so an uppercase id is rejected as "invalid event".
  let hashStr = hashData.hex.toLowerAscii()
  var eventId = ""
  for i in 0 ..< 32:
    eventId.add(hashStr[i*2..i*2+1])

  var hashBytes: array[32, byte]
  for i in 0 ..< 32:
    hashBytes[i] = parseHexInt(hashStr[i*2..i*2+1]).byte
  let msgRes = SkMessage.fromBytes(hashBytes)
  if not msgRes.isOk: return
  let msg = msgRes.value

  let rng: secp256k1.Rng = proc(data: var openArray[byte]): bool =
    for i in 0..<data.len:
      data[i] = byte(rand(255))
    true
  let sigRes = seckey.signSchnorr(msg, rng)
  if not sigRes.isOk: return
  let sig = sigRes.value
  let sigHex = ($sig).toLowerAscii()

  let eventMsg = %*[
    "EVENT",
    {
      "id": eventId, "pubkey": pubkeyHex, "created_at": createdAt,
      "kind": 1, "tags": tags, "content": content, "sig": sigHex
    }
  ]

  # Optimistically show our own post in the timeline (tagged via Nosterm).
  # It will be de-duplicated when the relay echoes it back.
  let localEvent = NostrEvent(id: eventId, pubkey: pubkeyHex, content: content,
                              createdAt: createdAt, client: "Nosterm")
  insertEvent(localEvent)

  try:
    asyncCheck sendToRelays($eventMsg)
  except CatchableError:
    discard

# --------------------------------------------------
# 3b. Mention rendering (NIP-27 nostr:npub tokens)
# --------------------------------------------------
# Convert on-wire mention tokens (nostr:npub1... / npub1...) into a readable
# "@displayName" (or "@npub…short" when unknown) for display.
proc displayContent(content: string): string =
  result = ""
  var i = 0
  let n = content.len
  while i < n:
    var k = i
    if k + 6 <= n and content[k .. k + 5] == "nostr:":
      k = k + 6
    if k + 5 <= n and content[k .. k + 4] == "npub1":
      var j = k + 5
      while j < n and Bech32Charset.find(content[j]) != -1: j.inc
      let npub = content[k ..< j]
      let pk = decodeNpubToHex(npub)
      if pk != "" and profileCache.hasKey(pk.toLowerAscii()):
        result.add("@" & profileCache[pk.toLowerAscii()])
      elif pk != "":
        let shortEnd = min(npub.high, 5 + 7)
        result.add("@" & npub[5 .. shortEnd] & "…")
      else:
        result.add(npub)
      i = j
    else:
      result.add(content[i])
      i.inc

# --------------------------------------------------
# 3c. Raw UTF-8 rune reader (for input / mention modes)
# --------------------------------------------------
# illwill's getKey only reads one byte at a time, so multi-byte UTF-8
# (e.g. Japanese) is mangled. Read stdin directly and assemble full runes.
proc drainStdin(): bool =
  var pfd: TPollFd
  pfd.fd = 0
  pfd.events = 1'i16   # POLLIN
  if poll(addr(pfd), 1, 0) <= 0: return false
  var buf: array[256, byte]
  let r = read(0, addr(buf), 256)
  if r <= 0: return false
  for i in 0 ..< r: pendingInput.add(buf[i])
  result = true

proc nextRune(): Rune =
  if pendingInput.len == 0:
    if not drainStdin(): return Rune(0)
  if pendingInput.len == 0: return Rune(0)

  # Escape sequences (e.g. arrow keys) start with ESC.
  if pendingInput[0] == byte('\e'):
    if pendingInput.len == 1:
      var pfd: TPollFd
      pfd.fd = 0; pfd.events = 1'i16
      if poll(addr(pfd), 1, 30) > 0:
        discard drainStdin()
      else:
        pendingInput = @[]
        return Rune(int('\e'))
    if pendingInput.len >= 2 and (pendingInput[1] == byte('[') or pendingInput[1] == byte('O')):
      var i = 1
      while i < pendingInput.len:
        let c = pendingInput[i]
        if (c >= byte('A') and c <= byte('Z')) or c == byte('~') or (c >= byte('a') and c <= byte('z')):
          case c
          of byte('A'): pendingInput = pendingInput[i + 1 .. ^1]; return RuneUp
          of byte('B'): pendingInput = pendingInput[i + 1 .. ^1]; return RuneDown
          of byte('C'): pendingInput = pendingInput[i + 1 .. ^1]; return RuneRight
          of byte('D'): pendingInput = pendingInput[i + 1 .. ^1]; return RuneLeft
          else: discard
          i.inc
          break
        i.inc
      pendingInput = pendingInput[i .. ^1]
      return Rune(0)
    else:
      pendingInput = @[]
      return Rune(int('\e'))

  # Assemble a full UTF-8 rune from leading byte.
  let b0 = pendingInput[0]
  var need = 1
  if (b0 and 0xE0) == 0xC0: need = 2
  elif (b0 and 0xF0) == 0xE0: need = 3
  elif (b0 and 0xF8) == 0xF0: need = 4
  if pendingInput.len < need:
    if not drainStdin(): return Rune(0)
  if pendingInput.len < need: return Rune(0)
  var s = ""
  for i in 0 ..< need: s.add(char(pendingInput[i]))
  pendingInput = pendingInput[need .. ^1]
  result = s.runeAt(0)

# --------------------------------------------------
# 3d. Input-mode key handling (UTF-8 aware)
# --------------------------------------------------
proc handleInputRune(ru: Rune) =
  # Ignore arrow-key sentinels (only meaningful in the mention picker).
  if ru == RuneUp or ru == RuneDown or ru == RuneLeft or ru == RuneRight:
    return
  # Ctrl+L forces a full timeline rebuild + repaint.
  if ru.ord == 12:
    refetchTimeline()
    return
  if ru == Rune(int('\e')):
    appMode = AppMode.ModeNormal
    inputBuffer = ""
    mentionMap.clear()
    mentionAnchor = -1
    hideTermCursor()
    needsRedraw = true
  elif ru == Rune(int('\n')) or ru == Rune(int('\r')):
    if inputBuffer.strip() != "":
      # Rewrite friendly "@name" mentions into canonical nostr:npub tokens and
      # collect the corresponding pubkeys for the "p" tags.
      var content = inputBuffer
      var mentionPks: seq[string] = @[]
      for name, pk in mentionMap:
        let tok = "@" & name
        if tok in content:
          content = content.replace(tok, "nostr:" & encodeBech32("npub", hexToBytes(pk)))
          mentionPks.add(pk)
      asyncCheck sendNostrPost(content, mentionPks)
      inputBuffer = ""
      mentionMap.clear()
      mentionAnchor = -1
    appMode = AppMode.ModeNormal
    hideTermCursor()
    needsRedraw = true
  elif ru == Rune(0x7f) or ru == Rune(0x08):   # DEL / Backspace
    if inputBuffer.len > 0:
      let runes = inputBuffer.toRunes
      if runes.len > 0:
        inputBuffer = $runes[0 .. ^2]
      needsRedraw = true
  elif ru == Rune(int('@')):
    # Open the mention picker. The text typed after '@' filters the list.
    if profileCache.len > 0 and displayWidth(inputBuffer) + 1 <= cols - 2 - 4:
      inputBuffer.add("@")
      mentionAnchor = inputBuffer.len - 1
      mentionSel = 0
      appMode = AppMode.ModeMention
      refreshMentionFilter()
      needsRedraw = true
    elif displayWidth(inputBuffer) + 1 <= cols - 2 - 4:
      inputBuffer.add("@")
      needsRedraw = true
  else:
    let ch = $ru
    if displayWidth(inputBuffer) + displayWidth(ch) <= cols - 2 - 4:
      inputBuffer.add(ch)
      needsRedraw = true

# --------------------------------------------------
# 3e. Mention-picker key handling
# --------------------------------------------------
# Rebuild the candidate list from the text typed after the triggering '@'.
proc refreshMentionFilter() =
  if mentionAnchor < 0 or mentionAnchor >= inputBuffer.len:
    mentionList = @[]
    return
  let start = mentionAnchor + 1
  let filter = if start < inputBuffer.len: inputBuffer[start .. inputBuffer.high].toLowerAscii
               else: ""
  mentionList = @[]
  for pk, nm in profileCache:
    if filter == "" or nm.toLowerAscii().contains(filter):
      mentionList.add((nm, pk))
  mentionSel = 0

proc handleMentionRune(ru: Rune) =
  if ru == RuneUp:
    if mentionList.len > 0:
      mentionSel = (mentionSel + mentionList.len - 1) mod mentionList.len
      needsRedraw = true
  elif ru == RuneDown:
    if mentionList.len > 0:
      mentionSel = (mentionSel + 1) mod mentionList.len
      needsRedraw = true
  elif ru == Rune(int('\e')):
    # Cancel: drop the '@' and the filter text that was typed.
    if mentionAnchor >= 0:
      if mentionAnchor > 0:
        inputBuffer = inputBuffer[0 .. mentionAnchor - 1]
      else:
        inputBuffer = ""
    appMode = AppMode.ModeInput
    needsRedraw = true
  elif ru == Rune(int('\n')) or ru == Rune(int('\r')):
    # Confirm: replace the typed filter (after '@') with the chosen name.
    if mentionList.len > 0 and mentionAnchor >= 0:
      let sel = mentionList[mentionSel]
      inputBuffer = inputBuffer[0 .. mentionAnchor] & sel.name
      mentionMap[sel.name] = sel.pubkey
    appMode = AppMode.ModeInput
    needsRedraw = true
  elif ru == Rune(0x7f) or ru == Rune(0x08):   # DEL / Backspace
    if inputBuffer.len > 0:
      let runes = inputBuffer.toRunes
      if runes.len > 0:
        inputBuffer = $runes[0 .. ^2]
      if inputBuffer.len <= mentionAnchor:
        appMode = AppMode.ModeInput
      else:
        refreshMentionFilter()
      needsRedraw = true
  else:
    # Treat any other character as filter input.
    let ch = $ru
    if displayWidth(inputBuffer) + displayWidth(ch) <= cols - 2 - 4:
      inputBuffer.add(ch)
      refreshMentionFilter()
      needsRedraw = true

# Type an emoji (or any text) to react to the focused post, then Enter to send.
proc handleReactionRune(ru: Rune) =
  if ru == RuneUp or ru == RuneDown or ru == RuneLeft or ru == RuneRight:
    return
  if ru.ord == 12:   # Ctrl+L
    refetchTimeline()
    return
  if ru == Rune(int('\e')):
    appMode = AppMode.ModeNormal
    reactionBuffer = ""
    hideTermCursor()
    needsRedraw = true
    return
  if ru == Rune(int('\n')) or ru == Rune(int('\r')):
    let emoji = reactionBuffer.strip()
    let t = currentSelectedEvent()
    if emoji != "" and t.id != "":
      asyncCheck sendReaction(t.id, t.pubkey, emoji)
    appMode = AppMode.ModeNormal
    reactionBuffer = ""
    hideTermCursor()
    needsRedraw = true
    return
  if ru == Rune(0x7f) or ru == Rune(0x08):   # DEL / Backspace
    if reactionBuffer.len > 0:
      let runes = reactionBuffer.toRunes
      reactionBuffer = $runes[0 .. ^2]
      needsRedraw = true
    return
  let ch = $ru
  if displayWidth(reactionBuffer) + displayWidth(ch) <= cols - 2 - 4:
    reactionBuffer.add(ch)
    needsRedraw = true

# --------------------------------------------------
# 4. Profile fetch requests (sent to read relays)
# --------------------------------------------------
proc requestProfiles(pubkeys: seq[string]) {.async.} =
  if pubkeys.len == 0: return
  let conns = relayConns
  let subId = "profile-fetch-" & $getTime().toUnix()
  var authorsJson = newJArray()
  for pk in pubkeys:
    authorsJson.add(%* pk)
  let reqMessage = %*["REQ", subId, {"kinds": [0], "authors": authorsJson, "limit": pubkeys.len}]
  for rc in conns:
    if rc.read:
      try:
        await rc.ws.send($reqMessage)
      except CatchableError:
        discard

proc fetchProfiles(pubkeys: seq[string]) =
  if pubkeys.len == 0: return
  asyncCheck requestProfiles(pubkeys)

# --------------------------------------------------
# 5. Multi-relay connections (read / write flags)
# --------------------------------------------------
# Broadcast a message to every relay configured for writing.
proc sendToRelays(msg: string) {.async.} =
  let conns = relayConns
  for rc in conns:
    if rc.write:
      try:
        await rc.ws.send(msg)
      except CatchableError:
        discard

# Parse one websocket packet (EVENT messages) from any relay.
proc processPacket(packet: string) =
  try:
    let parsed = parseJson(packet)
    if parsed.kind == JArray and parsed.len >= 3:
      let msgType = parsed[0].getStr()
      if msgType == "EVENT":
        let event = parsed[2]
        let kind = event["kind"].getInt()
        let pubkey = event["pubkey"].getStr()

        if kind == 0:
          try:
            let contentJson = parseJson(event["content"].getStr())
            var name = ""
            if contentJson.hasKey("display_name") and contentJson["display_name"].getStr() != "":
              name = contentJson["display_name"].getStr()
            elif contentJson.hasKey("name") and contentJson["name"].getStr() != "":
              name = contentJson["name"].getStr()
            if name != "":
              profileCache[pubkey.toLowerAscii()] = name
              needsRedraw = true
          except CatchableError:
            discard

        elif kind == 1:
          let content = event["content"].getStr()
          let createdAt = event["created_at"].getInt()
          let eventId = event["id"].getStr()
          var clientName = ""
          if event.hasKey("tags") and event["tags"].kind == JArray:
            for t in event["tags"]:
              if t.kind == JArray and t.len >= 2:
                if t[0].getStr() == "client":
                  clientName = t[1].getStr()
          let newEvent = NostrEvent(id: eventId, pubkey: pubkey, content: content,
                                   createdAt: createdAt, client: clientName)
          insertEvent(newEvent)

        elif kind == 10002:
          # Account relay list: collect candidates for the manual picker.
          if fetchingAccountRelays:
            collectAccountRelay(event["content"].getStr())

        elif kind == 7:
          # Reaction (NIP-25): aggregate by target event + emoji + reactor.
          let content = event["content"].getStr()
          var eId = ""
          var pId = ""
          if event.hasKey("tags") and event["tags"].kind == JArray:
            for t in event["tags"]:
              if t.kind == JArray and t.len >= 2:
                if t[0].getStr() == "e": eId = t[1].getStr()
                elif t[0].getStr() == "p": pId = t[1].getStr()
          if eId != "":
            let pk = event["pubkey"].getStr().toLowerAscii()
            var dup = false
            if reactions.hasKey(eId):
              for r in reactions[eId]:
                if r.emoji == content and r.pubkey == pk: dup = true
            else:
              reactions[eId] = @[]
            if not dup:
              reactions[eId].add((emoji: content, pubkey: pk))
              needsRedraw = true
  except CatchableError:
    discard

# Collect relay candidates from the account's kind 10002 list (manual picker).
proc collectAccountRelay(content: string) =
  try:
    let arr = parseJson(content)
    if arr.kind != JArray: return
    for item in arr:
      if item.kind != JObject: continue
      if not item.hasKey("url"): continue
      let url = item["url"].getStr()
      if url == "": continue
      let r = if item.hasKey("read"): item["read"].getBool() else: true
      let w = if item.hasKey("write"): item["write"].getBool() else: true
      var found = false
      for a in accountRelays:
        if a.url == url:
          found = true
          break
      if not found:
        accountRelays.add((url: url, read: r, write: w))
        needsRedraw = true
  except CatchableError:
    discard

# Ask every read relay for the account's kind 10002 list, then show a picker.
proc fetchAccountRelays() =
  if myPubkeyHex == "": return
  fetchingAccountRelays = true
  accountRelays = @[]
  relayPickSel = 0
  let conns = relayConns
  let subId = "nosterm-acct-" & $getTime().toUnix()
  let req = %*["REQ", subId, {"kinds": [10002], "authors": [myPubkeyHex], "limit": 1}]
  for rc in conns:
    if rc.read:
      let ws = rc.ws
      asyncCheck (proc() {.async.} =
        try: await ws.send($req) except CatchableError: discard)()
  appMode = ModeRelayPick
  needsRedraw = true

# One receiver task per relay connection.
proc relayRecv(url: string, read: bool, write: bool, gen: int) {.async.} =
  while gen == relayGen:
    var ws: WebSocket
    try:
      ws = await newWebSocket(url)
    except CatchableError:
      await sleepAsync(5000)
      continue
    # Register the live connection so we can broadcast to it.
    relayConns.add(RelayConn(url: url, read: read, write: write, ws: ws, gen: gen))
    if read:
      try:
        await ws.send($(%*["REQ", "nosterm-sub", {"kinds": [0, 1], "limit": 60}]))
      except CatchableError:
        discard
    while gen == relayGen:
      try:
        let packet = await ws.receiveStrPacket()
        if packet == "": break
        if read: processPacket(packet)
      except CatchableError:
        break
    try: ws.close()
    except CatchableError: discard
    for i in countdown(relayConns.high, 0):
      if relayConns[i].gen == gen and relayConns[i].ws == ws:
        relayConns.delete(i)
    await sleepAsync(2000)

# (Re)connect to every configured relay, tearing down old connections.
proc applyRelayConfig() =
  relayGen.inc
  relayConns = @[]
  for rc in relayConfigs:
    if rc.read or rc.write:
      asyncCheck relayRecv(rc.url, rc.read, rc.write, relayGen)

# Clear the timeline and re-request kind 0/1 from every read relay. Used by the
# "full rebuild" key (Ctrl+L) to recover from a corrupted layout / stale state.
proc refetchTimeline() =
  timeline = @[]
  selectedEventId = ""
  scrollOffset = 0
  reactions = initTable[string, seq[tuple[emoji: string, pubkey: string]]]()
  let conns = relayConns
  let subId = "nosterm-refresh-" & $getTime().toUnix()
  let req = %*["REQ", subId, {"kinds": [0, 1], "limit": 60}]
  for rc in conns:
    if rc.read:
      let ws = rc.ws
      asyncCheck (proc() {.async.} =
        try: await ws.send($req) except CatchableError: discard)()
  forceRedraw = true
  needsRedraw = true

# Move the focused post selection (delta > 0 = newer, < 0 = older).
proc moveSelection(delta: int) =
  if timeline.len == 0:
    selectedEventId = ""
    return
  var idx = -1
  if selectedEventId != "":
    for i in 0 .. timeline.high:
      if timeline[i].id == selectedEventId: idx = i; break
  if idx == -1: idx = timeline.high
  idx = clamp(idx + delta, 0, timeline.high)
  selectedEventId = timeline[idx].id
  needsRedraw = true

# Resolve the currently focused post: the explicitly selected one, or the
# newest (timeline is sorted oldest-first, so index high = newest).
proc currentSelectedEvent(): NostrEvent =
  if timeline.len == 0:
    return NostrEvent(id: "", pubkey: "", content: "", createdAt: 0, client: "")
  if selectedEventId != "":
    for ev in timeline:
      if ev.id == selectedEventId: return ev
  return timeline[timeline.high]

# Send a reaction (kind 7) to a post, tagging the target event and author.
proc sendReaction(targetId, targetAuthor, emoji: string) {.async.} =
  if savedSecKeyHex == "" or targetId == "": return
  let seckeyRes = SkSecretKey.fromHex(savedSecKeyHex)
  if not seckeyRes.isOk: return
  let seckey = seckeyRes.value
  let pubkey = seckey.toPublicKey()
  let pubkeyHex = $(pubkey.toXOnly())

  let createdAt = getTime().toUnix()
  let tags = newJArray()
  tags.add(%* ["e", targetId])
  tags.add(%* ["p", targetAuthor])
  tags.add(%* ["client", "Nosterm"])

  let serializeArray = %*[0, pubkeyHex, createdAt, 7, tags, emoji]
  let hashData = computeSHA256($serializeArray)
  let hashStr = hashData.hex.toLowerAscii()
  var eventId = ""
  for i in 0 ..< 32:
    eventId.add(hashStr[i*2 .. i*2+1])
  var hashBytes: array[32, byte]
  for i in 0 ..< 32:
    hashBytes[i] = parseHexInt(hashStr[i*2 .. i*2+1]).byte
  let msgRes = SkMessage.fromBytes(hashBytes)
  if not msgRes.isOk: return
  let msg = msgRes.value
  let rng: secp256k1.Rng = proc(data: var openArray[byte]): bool =
    for i in 0 ..< data.len:
      data[i] = byte(rand(255))
    true
  let sigRes = seckey.signSchnorr(msg, rng)
  if not sigRes.isOk: return
  let sigHex = ($sigRes.value).toLowerAscii()
  let eventMsg = %*["EVENT", {
    "id": eventId, "pubkey": pubkeyHex, "created_at": createdAt,
    "kind": 7, "tags": tags, "content": emoji, "sig": sigHex
  }]
  asyncCheck sendToRelays($eventMsg)
  # Show our own reaction immediately (deduped against the relay echo).
  var dup = false
  if reactions.hasKey(targetId):
    for r in reactions[targetId]:
      if r.emoji == emoji and r.pubkey == pubkeyHex.toLowerAscii(): dup = true
  else:
    reactions[targetId] = @[]
  if not dup:
    reactions[targetId].add((emoji: emoji, pubkey: pubkeyHex.toLowerAscii()))
  needsRedraw = true

# Insert an event into the timeline (dedup by id, keep sorted by createdAt,
# adjust scroll, fetch missing profiles). Shared by the receiver and the poster.
proc insertEvent(ev: NostrEvent) =
  # Skip empty posts (spam / invalid).
  if ev.content.strip() == "":
    return

  for existing in timeline:
    if existing.id == ev.id:
      return   # duplicate

  # Binary search insert (oldest first = index 0)
  var left = 0
  var right = timeline.len
  while left < right:
    let mid = (left + right) div 2
    if timeline[mid].createdAt <= ev.createdAt:
      left = mid + 1
    else:
      right = mid
  timeline.insert(ev, left)

  if timeline.len > 150:
    timeline.delete(0)

  if scrollOffset > 0:
    scrollOffset = min(scrollOffset + 1, timeline.high)

  let pubkeyLower = ev.pubkey.toLowerAscii()
  if not profileCache.hasKey(pubkeyLower) and pubkeyLower notin pendingProfiles:
    pendingProfiles.add(pubkeyLower)
    fetchProfiles(@[ev.pubkey])

  needsRedraw = true

# --------------------------------------------------
# 6. Main TUI loop
# --------------------------------------------------
proc main() {.async.} =
  illwillInit()
  randomize()
  # We render with our own wide-char-aware row diff (renderToTerminal), so
  # illwill's own double-buffered display is not used.
  setControlCHook(exitProc)
  hideTermCursor()

  let keyLoaded = loadConfig()
  if not keyLoaded:
    appMode = AppMode.ModeNormal

  # Derive our own pubkey so we can fetch the account's relay list (kind 10002).
  if savedSecKeyHex != "":
    let skRes = SkSecretKey.fromHex(savedSecKeyHex)
    if skRes.isOk:
      myPubkeyHex = $skRes.value.toPublicKey().toXOnly()

  let (initCols, initRows) = terminalSize()
  if initCols > 0: cols = initCols
  if initRows > 0: rows = initRows
  var tb = newTerminalBuffer(cols, rows)

  # Connect to all configured relays (read + write).
  applyRelayConfig()

  while true:
    var key: Key = Key.None
    if appMode == AppMode.ModeInput or appMode == AppMode.ModeMention or
       appMode == AppMode.ModeReaction:
      # Read raw UTF-8 runes so Japanese / multi-byte input is captured intact.
      while true:
        let ru = nextRune()
        if ru == Rune(0): break
        if appMode == AppMode.ModeInput:
          handleInputRune(ru)
        elif appMode == AppMode.ModeMention:
          handleMentionRune(ru)
        else:
          handleReactionRune(ru)
    else:
      key = getKeyWithTimeout(0)

    # Ctrl+L forces a full timeline rebuild + repaint.
    if key == Key.CtrlL:
      refetchTimeline()
      continue

    if appMode == AppMode.ModeKeyInput:
      case key
      of Key.Escape:
        if settingsActive: appMode = AppMode.ModeSettings
        else: appMode = AppMode.ModeNormal
        keyInputBuffer = ""
        hideTermCursor()
        needsRedraw = true
      of Key.Enter:
        if applyNsec(keyInputBuffer.strip()):
          # Recompute our pubkey + reconnect to pick up the account relay list.
          if savedSecKeyHex != "":
            let skRes = SkSecretKey.fromHex(savedSecKeyHex)
            if skRes.isOk:
              myPubkeyHex = $skRes.value.toPublicKey().toXOnly()
          applyRelayConfig()
          if settingsActive: appMode = AppMode.ModeSettings
          else: appMode = AppMode.ModeNormal
          keyInputBuffer = ""
          hideTermCursor()
          needsRedraw = true
        else:
          keyInputBuffer = "INVALID nsec! Try again."
          needsRedraw = true
      of Key.Backspace:
        if keyInputBuffer.len > 0 and keyInputBuffer != "INVALID nsec! Try again.":
          keyInputBuffer.setLen(keyInputBuffer.len - 1)
          needsRedraw = true
      of Key.None: discard
      else:
        if key != Key.None:
          let keyChar = chr(int(key))
          if keyChar != '\0':
            if keyInputBuffer == "INVALID nsec! Try again.": keyInputBuffer = ""
            keyInputBuffer.add(keyChar)
            needsRedraw = true

    elif appMode == AppMode.ModeNormal:
      case key
      of Key.Q, Key.Escape: exitProc()
      of Key.I:
        appMode = AppMode.ModeInput
        needsRedraw = true
        showTermCursor()
      of Key.S:
        settingsActive = false
        appMode = AppMode.ModeSettings
        needsRedraw = true
      of Key.F:
        japaneseOnly = not japaneseOnly
        needsRedraw = true
      of Key.Up, Key.K:
        if timeline.len > 0:
          scrollOffset = min(scrollOffset + 1, timeline.high)
          needsRedraw = true
      of Key.Down, Key.J:
        if scrollOffset > 0:
          scrollOffset = max(scrollOffset - 1, 0)
          needsRedraw = true
      of Key.L:
        scrollOffset = 0
        needsRedraw = true
      of Key.Left:
        moveSelection(-1)
      of Key.Right:
        moveSelection(1)
      of Key.E:
        # Enter emoji-input mode to react to the focused post.
        if currentSelectedEvent().id != "":
          reactionBuffer = ""
          appMode = AppMode.ModeReaction
          needsRedraw = true
          showTermCursor()
      of Key.R:
        if relayConfigs.len > 0: relaySel = 0
        appMode = AppMode.ModeRelay
        needsRedraw = true
      of Key.None:
        let (newCols, newRows) = terminalSize()
        if newCols > 0 and newRows > 0 and (newCols != cols or newRows != rows):
          cols = newCols; rows = newRows
          tb = newTerminalBuffer(cols, rows)
          needsRedraw = true
      else: discard

    elif appMode == AppMode.ModeRelay:
      case key
      of Key.Escape:
        if settingsActive:
          appMode = AppMode.ModeSettings
        else:
          appMode = AppMode.ModeNormal
        needsRedraw = true
      of Key.Up, Key.K:
        if relayConfigs.len > 0:
          relaySel = (relaySel + relayConfigs.len - 1) mod relayConfigs.len
          needsRedraw = true
      of Key.Down, Key.J:
        if relayConfigs.len > 0:
          relaySel = (relaySel + 1) mod relayConfigs.len
          needsRedraw = true
      of Key.R:
        if relayConfigs.len > 0:
          relayConfigs[relaySel].read = not relayConfigs[relaySel].read
          saveConfig(); applyRelayConfig()
          needsRedraw = true
      of Key.W:
        if relayConfigs.len > 0:
          relayConfigs[relaySel].write = not relayConfigs[relaySel].write
          saveConfig(); applyRelayConfig()
          needsRedraw = true
      of Key.A:
        relayAddBuffer = ""
        appMode = AppMode.ModeRelayAdd
        needsRedraw = true
        showTermCursor()
      of Key.D:
        if relayConfigs.len > 0:
          relayConfigs.delete(relaySel)
          if relaySel >= relayConfigs.len: relaySel = max(0, relayConfigs.len - 1)
          saveConfig(); applyRelayConfig()
          needsRedraw = true
      of Key.F:
        fetchAccountRelays()
      else: discard

    elif appMode == AppMode.ModeRelayAdd:
      case key
      of Key.Escape:
        appMode = AppMode.ModeRelay
        if settingsActive: appMode = AppMode.ModeSettings
        hideTermCursor()
        needsRedraw = true
      of Key.Enter:
        let url = relayAddBuffer.strip()
        if url.startsWith("wss://") or url.startsWith("ws://"):
          relayConfigs.add(RelayConfig(url: url, read: true, write: true))
          saveConfig(); applyRelayConfig()
        appMode = AppMode.ModeRelay
        if settingsActive: appMode = AppMode.ModeSettings
        hideTermCursor()
        needsRedraw = true
      of Key.Backspace:
        if relayAddBuffer.len > 0:
          relayAddBuffer.setLen(relayAddBuffer.len - 1)
          needsRedraw = true
      of Key.None: discard
      else:
        if key != Key.None:
          let keyChar = chr(int(key))
          if keyChar != '\0' and keyChar != '\n' and keyChar != '\r':
            relayAddBuffer.add(keyChar)
            needsRedraw = true

    elif appMode == AppMode.ModeRelayPick:
      case key
      of Key.Escape:
        fetchingAccountRelays = false
        appMode = AppMode.ModeRelay
        if settingsActive: appMode = AppMode.ModeSettings
        needsRedraw = true
      of Key.Up, Key.K:
        if accountRelays.len > 0:
          relayPickSel = (relayPickSel + accountRelays.len - 1) mod accountRelays.len
          needsRedraw = true
      of Key.Down, Key.J:
        if accountRelays.len > 0:
          relayPickSel = (relayPickSel + 1) mod accountRelays.len
          needsRedraw = true
      of Key.Enter:
        if accountRelays.len > 0 and relayPickSel < accountRelays.len:
          let cand = accountRelays[relayPickSel]
          var found = false
          for rc in relayConfigs:
            if rc.url == cand.url:
              found = true
              break
          if not found:
            relayConfigs.add(RelayConfig(url: cand.url, read: cand.read, write: cand.write))
            saveConfig(); applyRelayConfig()
          accountRelays.delete(relayPickSel)
          if relayPickSel >= accountRelays.len:
            relayPickSel = max(0, accountRelays.len - 1)
          needsRedraw = true
      else: discard

    elif appMode == AppMode.ModeSettings:
      case key
      of Key.Escape, Key.Q:
        settingsActive = false
        appMode = AppMode.ModeNormal
        needsRedraw = true
      of Key.R:
        settingsActive = true
        if relayConfigs.len > 0: relaySel = 0
        appMode = AppMode.ModeRelay
        needsRedraw = true
      of Key.K:
        settingsActive = true
        appMode = AppMode.ModeKeyInput
        keyInputBuffer = ""
        needsRedraw = true
        showTermCursor()
      of Key.J:
        japaneseOnly = not japaneseOnly
        needsRedraw = true
      else: discard

    # ModeInput / ModeMention are driven by the raw rune reader above.

    # --------------------------------------------------
    # 7. Screen rendering
    # --------------------------------------------------
    if needsRedraw:
      tb.clear()
      # Draw borders first (they persist)
      tb.drawRect(0, 0, cols - 1, rows - 1)
      tb.write(2, 0, "[ Nosterm ]", illwill.fgYellow)

      if appMode == AppMode.ModeKeyInput:
        tb.write(4, 3, "Welcome to Nosterm!", illwill.fgYellow)
        tb.write(4, 5, "Please enter your Nostr secret key (nsec1...):", illwill.fgWhite)
        tb.drawHorizLine(4, cols - 5, 7)
        
        var maskedKey = ""
        for idx, c in keyInputBuffer:
          if idx < 9: maskedKey.add(c)
          else: maskedKey.add('*')
          
        tb.write(4, 6, "> " & maskedKey, illwill.fgCyan)
        tb.write(4, rows - 3, "Press [Enter] to Save & Start | [Esc] to Cancel", illwill.fgWhite)

      elif appMode == AppMode.ModeSettings:
        tb.write(2, 1, "Settings", illwill.fgYellow)
        tb.write(2, 3, "Account key (nsec):", illwill.fgWhite)
        let keyMask = if savedNsec != "": "nsec1" & "*".repeat(max(1, savedNsec.len - 8)) else: "(not set)"
        tb.write(4, 4, keyMask, illwill.fgCyan)
        tb.write(2, 6, "Japanese-only filter:", illwill.fgWhite)
        tb.write(4, 7, if japaneseOnly: "ON" else: "OFF", illwill.fgCyan)
        tb.write(2, 9, "Relays configured:", illwill.fgWhite)
        tb.write(4, 10, $relayConfigs.len, illwill.fgCyan)
        tb.drawHorizLine(2, cols - 3, 12)
        tb.write(2, 13, "R  Manage relays (add / remove / read-write)", illwill.fgWhite)
        tb.write(2, 14, "K  Change account key (nsec)", illwill.fgWhite)
        tb.write(2, 15, "J  Toggle Japanese-only filter", illwill.fgWhite)
        tb.write(2, rows - 3, fitToWidth("R:Relays  K:Key  J:Filter  Esc:Back to timeline", cols - 4), illwill.fgWhite)

      elif appMode == AppMode.ModeRelay:
        tb.write(2, 1, "Relays", illwill.fgYellow)
        tb.write(2, 2, fmt" {relayConfigs.len} configured", illwill.fgWhite)
        let listTop = 4
        for idx in 0 ..< relayConfigs.len:
          let y = listTop + idx
          if y >= rows - 3: break
          let rc = relayConfigs[idx]
          var connected = false
          for c in relayConns:
            if c.gen == relayGen and c.url == rc.url:
              connected = true
              break
          let sel = (idx == relaySel)
          let mark = if sel: "▶ " else: "  "
          let rchk = if rc.read: "[x]" else: "[ ]"
          let wchk = if rc.write: "[x]" else: "[ ]"
          let status = if connected: "●" else: "○"
          var lineStr = mark & status & " " & rchk & "R " & wchk & "W  " & rc.url
          lineStr = fitToWidth(lineStr, cols - 4)
          if sel: writeLine(tb, 2, y, lineStr, illwill.fgYellow)
          else: writeLine(tb, 2, y, lineStr, illwill.fgWhite)
        tb.write(2, rows - 3, fitToWidth("↑/↓ select  r:Read  w:Write  a:Add  d:Delete  f:Fetch acct  Esc:Back", cols - 4), illwill.fgWhite)

      elif appMode == AppMode.ModeRelayAdd:
        tb.write(2, 1, "Add Relay", illwill.fgYellow)
        tb.write(2, 3, "URL (wss://... or ws://...):", illwill.fgWhite)
        tb.drawHorizLine(2, cols - 3, 5)
        tb.write(4, 4, "> " & relayAddBuffer, illwill.fgCyan)
        tb.write(2, rows - 3, "Press [Enter] to Add | [Esc] to Cancel", illwill.fgWhite)

      elif appMode == AppMode.ModeRelayPick:
        tb.write(2, 1, "Relays from your account (kind 10002)", illwill.fgYellow)
        if accountRelays.len == 0:
          tb.write(2, 3, "Fetching... (or none found). Press [Esc] to go back.", illwill.fgWhite)
        else:
          for idx in 0 ..< accountRelays.len:
            let y = 3 + idx
            if y >= rows - 3: break
            let a = accountRelays[idx]
            let sel = (idx == relayPickSel)
            let mark = if sel: "▶ " else: "  "
            let rchk = if a.read: "[x]" else: "[ ]"
            let wchk = if a.write: "[x]" else: "[ ]"
            var added = false
            for rc in relayConfigs:
              if rc.url == a.url: added = true
            var lineStr = mark & rchk & "R " & wchk & "W  " & a.url & (if added: "  (already added)" else: "")
            lineStr = fitToWidth(lineStr, cols - 4)
            if sel: writeLine(tb, 2, y, lineStr, illwill.fgYellow)
            else: writeLine(tb, 2, y, lineStr, illwill.fgWhite)
          tb.write(2, rows - 3, fitToWidth("↑/↓ select  Enter add  Esc back", cols - 4), illwill.fgWhite)

      else:
        let statusText = if scrollOffset == 0: "[ LIVE - Tracking Latest ]" else: fmt"[ Scroll: {scrollOffset} (Press 'L' to Live) ]"
        let statusColor = if scrollOffset == 0: illwill.fgGreen else: illwill.fgMagenta
        tb.write(cols - 2 - statusText.len, 0, statusText, statusColor)
        
        tb.drawHorizLine(1, cols - 2, rows - 4)
        
        if appMode == AppMode.ModeNormal:
          tb.write(2, rows - 3, fitToWidth("i:Post S:Settings R:Relays F:JP ←/→:Select e:React K/J:Scroll L:Live Ctrl+L:Reload Q:Quit", cols - 4), illwill.fgWhite)
        elif appMode == AppMode.ModeMention:
          tb.write(2, rows - 3, fitToWidth("↑/↓ select  Enter choose  Esc cancel", cols - 4), illwill.fgYellow)
        elif appMode == AppMode.ModeReaction:
          tb.write(2, rows - 3, fitToWidth("type emoji + Enter to react  Esc cancel", cols - 4), illwill.fgYellow)
          let prompt = "react> "
          writeLine(tb, 2, rows - 2, prompt, illwill.fgCyan)
          writeLine(tb, 2 + prompt.len, rows - 2, reactionBuffer, illwill.fgWhite)
        else:
          tb.write(2, rows - 3, fitToWidth("TYPE MESSAGE + ENTER TO POST (ESC CANCEL)", cols - 4), illwill.fgYellow)

          let prompt = "> "
          writeLine(tb, 2, rows - 2, prompt, illwill.fgCyan)
          writeLine(tb, 2 + prompt.len, rows - 2, displayContent(inputBuffer), illwill.fgWhite)

        # Build visible items list (respecting japaneseOnly filter)
        var visibleItems: seq[int] = @[]
        for i in 0 .. timeline.high:
          if not (japaneseOnly and not containsJapanese(timeline[i].content)):
            visibleItems.add(i)
        
        let timelineBottomY = rows - 5
        let timelineTopY = 1
        var currentY = timelineBottomY

        let visibleCount = visibleItems.len
        if scrollOffset > visibleCount - 1 and visibleCount > 0:
          scrollOffset = visibleCount - 1
          needsRedraw = true

        if visibleCount > 0:
          let startIdx = visibleCount - 1 - scrollOffset
          let maxDisplayWidth = cols - 2
          let borderChar = TerminalChar(ch: Rune(0x2502), fg: illwill.fgWhite, bg: illwill.bgNone, style: {})

          for visibleIdx in countdown(startIdx, 0):
            if currentY < timelineTopY: break

            let i = visibleItems[visibleIdx]
            let ev = timeline[i]

            let displayName = if profileCache.hasKey(ev.pubkey.toLowerAscii()):
                                profileCache[ev.pubkey.toLowerAscii()]
                              else:
                                ev.pubkey[0..7]

            let isSelected = (ev.id == selectedEventId) or
                             (selectedEventId == "" and i == timeline.high)
            let selColor = if isSelected: illwill.fgYellow else: illwill.fgCyan

            let namePart = fmt"[{displayName}]"
            let viaLabel = if ev.client != "": "· via " & ev.client & ": " else: ""
            let viaColor = if ev.client.toLowerAscii() == "nosterm": illwill.fgGreen
                           else: illwill.fgWhite

            let viaPrefixWidth = displayWidth(viaLabel)
            let maxContentWidth = max(1, cols - 2 - viaPrefixWidth)
            let wrappedLines = wrapText(displayContent(ev.content), maxContentWidth)
            let nLines = 1 + wrappedLines.len

            # Display name on its own line (top of the post block).
            let nameY = currentY - nLines + 1
            if nameY >= timelineTopY:
              writeLine(tb, 1, nameY, namePart, selColor)
              tb[cols - 1, nameY] = borderChar

            # Content lines below; the first one carries the "via" badge.
            for li in 0 .. wrappedLines.high:
              let y = currentY - nLines + 2 + li
              if y < timelineTopY: break
              let contentPart = wrappedLines[li]
              let usedWidth = viaPrefixWidth + displayWidth(contentPart)
              let padWidth = max(0, maxDisplayWidth - usedWidth)
              let padStr = " ".repeat(padWidth)
              if li == 0 and viaLabel != "":
                writeLine(tb, 1, y, viaLabel, viaColor)
              writeLine(tb, 1 + viaPrefixWidth, y, contentPart & padStr,
                        if isSelected: illwill.fgYellow else: illwill.fgWhite)
              tb[cols - 1, y] = borderChar

            currentY = currentY - nLines

            # Reaction summary line (NIP-25), if any for this post.
            if reactions.hasKey(ev.id):
              let rs = reactions[ev.id]
              var counts = initTable[string, int]()
              for r in rs: counts[r.emoji] = counts.getOrDefault(r.emoji, 0) + 1
              var parts: seq[string] = @[]
              for k, v in pairs(counts): parts.add(k & " " & $v)
              let reactLine = parts.join("  ")
              if reactLine != "" and currentY >= timelineTopY:
                let rused = displayWidth(reactLine)
                let rpad = max(0, maxDisplayWidth - rused)
                writeLine(tb, 1, currentY, reactLine & " ".repeat(rpad),
                          if isSelected: illwill.fgYellow else: illwill.fgWhite)
                tb[cols - 1, currentY] = borderChar
                currentY -= 1

            # Separator line between posts (panel divider)
            if currentY >= timelineTopY:
              tb.drawHorizLine(1, cols - 2, currentY)
              tb[cols - 1, currentY] = borderChar
              currentY -= 1

      if appMode == AppMode.ModeMention:
        # Overlay a mention picker above the input line.
        let panelTop = max(2, rows - 14)
        let panelBottom = rows - 4
        tb.drawRect(1, panelTop, cols - 2, panelBottom)
        # Erase the timeline behind the panel so posts don't bleed through.
        for py in panelTop + 1 .. panelBottom - 1:
          tb.write(2, py, " ".repeat(max(1, cols - 4)), illwill.fgWhite)
        tb.write(3, panelTop, " Mention  ↑/↓ select  Enter choose  Esc cancel ", illwill.fgYellow)
        if mentionList.len > 0:
          let listTop = panelTop + 2
          let maxShow = max(1, panelBottom - listTop - 1)
          var viewStart = 0
          if mentionList.len > maxShow:
            viewStart = max(0, min(mentionSel - maxShow div 2, mentionList.len - maxShow))
          for idx in 0 ..< maxShow:
            let li = viewStart + idx
            if li >= mentionList.len: break
            let y = listTop + idx
            let sel = (li == mentionSel)
            let nm = mentionList[li].name
            let pkShort = mentionList[li].pubkey[0 .. 7]
            let lineStr = " " & (if sel: "▶ " else: "  ") & "@" & nm & "  (" & pkShort & ")"
            if sel:
              writeLine(tb, 3, y, lineStr, illwill.fgYellow)
            else:
              writeLine(tb, 3, y, lineStr, illwill.fgWhite)
          # redraw the input line on top of the panel's bottom edge
          let prompt = "> "
          writeLine(tb, 2, rows - 2, prompt, illwill.fgCyan)
          writeLine(tb, 2 + prompt.len, rows - 2, displayContent(inputBuffer), illwill.fgWhite)
        else:
          tb.write(3, panelTop + 2, " (no profiles loaded yet)", illwill.fgWhite)

      renderToTerminal(tb)
      needsRedraw = false

    # Cursor: reposition every frame so it never drifts to the bottom-right,
    # and only show it while actually typing text.
    if appMode == AppMode.ModeInput or appMode == AppMode.ModeMention:
      showTermCursor()
      setTermCursor(2 + 2 + displayWidth(displayContent(inputBuffer)), rows - 2)
    elif appMode == AppMode.ModeReaction:
      showTermCursor()
      setTermCursor(2 + 7 + displayWidth(reactionBuffer), rows - 2)
    elif appMode == AppMode.ModeKeyInput:
      showTermCursor()
      setTermCursor(4 + 2 + keyInputBuffer.len, 6)
    elif appMode == AppMode.ModeRelayAdd:
      showTermCursor()
      setTermCursor(4 + 2 + relayAddBuffer.len, 4)
    else:
      hideTermCursor()

    await sleepAsync(20)

waitFor main()