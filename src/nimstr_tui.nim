import std/[asyncdispatch, json, strformat, os, strutils, times, tables, unicode, random]
import std/terminal
import ws, illwill
import secp256k1
import nimSHA2

# =============================================================================
# nimstr_tui - Nostr TUI Client in Nim
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
proc displayWidth(text: string): int =
  result = 0
  for r in text.toRunes:
    if r.ord < 128:
      result += 1
    else:
      result += 2

# Write string at (x,y) with proper full-width handling.
# illwill 0.4.1 has no wide-char support: each buffer cell maps to one
# terminal column. A full-width char occupies 2 columns, so for it we write
# the rune to cell cx and a NUL rune to cx+1. The NUL outputs nothing, so the
# terminal cursor stays aligned for the following cells (writing a space there
# would advance the cursor an extra column and break alignment).
proc writeLine(tb: var TerminalBuffer, x, y: int, text: string, color: illwill.ForegroundColor) =
  if y < 0 or y >= tb.height: return
  var cx = x
  for r in text.toRunes:
    if r.ord >= 128:
      if cx + 1 >= tb.width - 1: break   # would overflow into right border
      tb[cx, y] = TerminalChar(ch: r, fg: color, bg: bgNone, style: {})
      tb[cx + 1, y] = TerminalChar(ch: Rune(0), fg: color, bg: bgNone, style: {})
      cx += 2
    else:
      if cx >= tb.width - 1: break
      tb[cx, y] = TerminalChar(ch: r, fg: color, bg: bgNone, style: {})
      cx += 1

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
# Bech32 (nsec) decode - pure Nim implementation
# --------------------------------------------------
const Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

proc decodeBech32(bechString: string): string =
  if not bechString.startsWith("nsec1"): return ""
  let dataPart = bechString[5..^1]
  
  var bytes5: seq[byte] = @[]
  for c in dataPart:
    let idx = Bech32Charset.find(c)
    if idx == -1: return ""
    bytes5.add(idx.byte)
    
  if bytes5.len < 6: return ""
  bytes5.setLen(bytes5.len - 6)

  var bytes8: seq[byte] = @[]
  var accumulator = 0.uint32
  var bits = 0
  for b in bytes5:
    accumulator = (accumulator shl 5) or b.uint32
    bits += 5
    while bits >= 8:
      bits -= 8
      bytes8.add(((accumulator shr bits) and 0xFF.uint32).byte)

  if bytes8.len != 32: return ""

  result = ""
  for b in bytes8:
    result.add(b.toHex(2).toLowerAscii())

# --------------------------------------------------
# 1. Type definitions and global state
# --------------------------------------------------
type
  NostrEvent = object
    id: string        # Event ID (for deduplication)
    pubkey: string    # Public key (hex, 64 chars)
    content: string   # Note content
    createdAt: int64  # Creation timestamp (Unix time, for sorting)

  AppMode = enum
    ModeNormal,   # Browse/scroll mode
    ModeInput,    # Post input mode
    ModeKeyInput  # nsec input mode

var timeline: seq[NostrEvent] = @[]
var profileCache = initTable[string, string]()  # pubkey(lowercase) -> display name
var needsRedraw = true
var scrollOffset = 0

var appMode = AppMode.ModeNormal
var inputBuffer = ""
var keyInputBuffer = ""
var savedSecKeyHex = ""
var globalWS: WebSocket
let configPath = getHomeDir() / ".nimstr_config"
var pendingProfiles: seq[string] = @[]
var japaneseOnly = false

# --------------------------------------------------
# Cleanup procedure
# --------------------------------------------------
proc exitProc() {.noconv.} =
  illwillDeinit()
  showCursor()
  quit(0)

# --------------------------------------------------
# 2. Config file read/write
# --------------------------------------------------
proc loadSecretKey(): bool =
  if fileExists(configPath):
    try:
      let nsec = readFile(configPath).strip()
      let hex = decodeBech32(nsec)
      if hex != "":
        savedSecKeyHex = hex
        return true
    except CatchableError:
      discard
  return false

proc saveSecretKey(nsec: string): bool =
  let hex = decodeBech32(nsec)
  if hex == "": return false
  try:
    writeFile(configPath, nsec)
    discard execShellCmd("chmod 600 " & quoteShell(configPath))
    savedSecKeyHex = hex
    return true
  except CatchableError:
    return false

# --------------------------------------------------
# 3. Nostr post sending (Schnorr signature)
# --------------------------------------------------
proc sendNostrPost(content: string) {.async.} =
  if globalWS == nil: return
  if savedSecKeyHex == "": return

  let seckeyRes = SkSecretKey.fromHex(savedSecKeyHex)
  if not seckeyRes.isOk: return
  let seckey = seckeyRes.value
  
  let pubkey = seckey.toPublicKey()
  let xonly = pubkey.toXOnly()
  let pubkeyHex = $xonly

  let createdAt = getTime().toUnix()
  let tags = newJArray()
  
  let serializeArray = %*[
    0, pubkeyHex, createdAt, 1, tags, content
  ]
  
  let hashData = computeSHA256($serializeArray)
  let hashStr = hashData.hex
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
  let sigHex = $sig

  let eventMsg = %*[
    "EVENT",
    {
      "id": eventId, "pubkey": pubkeyHex, "created_at": createdAt,
      "kind": 1, "tags": tags, "content": content, "sig": sigHex
    }
  ]

  try:
    await globalWS.send($eventMsg)
  except CatchableError:
    discard

# --------------------------------------------------
# 4. Profile fetch requests
# --------------------------------------------------
proc requestProfiles(pubkeys: seq[string]) {.async.} =
  if pubkeys.len == 0: return
  if globalWS == nil: return
  
  let subId = "profile-fetch-" & $getTime().toUnix()
  var authorsJson = newJArray()
  for pk in pubkeys:
    authorsJson.add(%* pk)
  
  let reqMessage = %*["REQ", subId, {"kinds": [0], "authors": authorsJson, "limit": pubkeys.len}]
  
  try:
    await globalWS.send($reqMessage)
  except CatchableError:
    discard

proc fetchProfiles(pubkeys: seq[string]) =
  if pubkeys.len == 0: return
  asyncCheck requestProfiles(pubkeys)

# --------------------------------------------------
# 5. Background Nostr event receiver
# --------------------------------------------------
proc recvNostrEvents() {.async.} =
  let relayUrl = "wss://yabu.me"
  let subscriptionId = "my-tui-app"
  let reqMessage = %*["REQ", subscriptionId, {"kinds": [0, 1], "limit": 60}]

  while true:
    try:
      globalWS = await newWebSocket(relayUrl)
      await globalWS.send($reqMessage)
    except CatchableError:
      await sleepAsync(5000)
      continue

    while true:
      try:
        let packet = await globalWS.receiveStrPacket()
        if packet == "": break

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
              let newEvent = NostrEvent(id: eventId, pubkey: pubkey, content: content, createdAt: createdAt)
              
              # Deduplication by event ID
              var isDuplicate = false
              for existing in timeline:
                if existing.id == eventId:
                  isDuplicate = true
                  break
              if isDuplicate: continue
              
              # Binary search insert (oldest first = index 0)
              var left = 0
              var right = timeline.len
              while left < right:
                let mid = (left + right) div 2
                if timeline[mid].createdAt <= createdAt:
                  left = mid + 1
                else:
                  right = mid
              timeline.insert(newEvent, left)
              
              if timeline.len > 150:
                timeline.delete(0)
              
              if scrollOffset > 0:
                scrollOffset = min(scrollOffset + 1, timeline.high)
              
              let pubkeyLower = pubkey.toLowerAscii()
              if not profileCache.hasKey(pubkeyLower) and pubkeyLower notin pendingProfiles:
                pendingProfiles.add(pubkeyLower)
                fetchProfiles(@[pubkey])
              
              needsRedraw = true

      except CatchableError:
        break

    globalWS.close()
    await sleepAsync(2000)

# --------------------------------------------------
# 6. Main TUI loop
# --------------------------------------------------
proc main() {.async.} =
  illwillInit()
  # illwill 0.4.1 has no wide-character support. Its double-buffered
  # diff-mode tracks the cursor by rune count, which desyncs on full-width
  # characters. Disable it so display() repaints each row from column 0,
  # keeping every row's alignment independent and correct.
  setDoubleBuffering(false)
  setControlCHook(exitProc)
  hideCursor()

  let keyLoaded = loadSecretKey()
  if not keyLoaded:
    appMode = AppMode.ModeNormal

  var (cols, rows) = terminalSize()
  if cols <= 0: cols = 80
  if rows <= 0: rows = 24
  var tb = newTerminalBuffer(cols, rows)

  discard recvNostrEvents()

  while true:
    var key = getKeyWithTimeout(0)
    
    if appMode == AppMode.ModeKeyInput:
      case key
      of Key.Escape:
        appMode = AppMode.ModeNormal
        keyInputBuffer = ""
        hideCursor()
        needsRedraw = true
      of Key.Enter:
        if saveSecretKey(keyInputBuffer.strip()):
          appMode = AppMode.ModeNormal
          keyInputBuffer = ""
          hideCursor()
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
        showCursor()
      of Key.S:
        appMode = AppMode.ModeKeyInput
        keyInputBuffer = ""
        needsRedraw = true
        showCursor()
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
      of Key.None:
        let (newCols, newRows) = terminalSize()
        if newCols > 0 and newRows > 0 and (newCols != cols or newRows != rows):
          cols = newCols; rows = newRows
          tb = newTerminalBuffer(cols, rows)
          needsRedraw = true
      else: discard

    elif appMode == AppMode.ModeInput:
      case key
      of Key.Escape:
        appMode = AppMode.ModeNormal
        inputBuffer = ""
        hideCursor()
        needsRedraw = true
      of Key.Enter:
        if inputBuffer.strip() != "":
          asyncCheck sendNostrPost(inputBuffer)
          inputBuffer = ""
        appMode = AppMode.ModeNormal
        hideCursor()
        needsRedraw = true
      of Key.Backspace:
        if inputBuffer.len > 0:
          inputBuffer.setLen(inputBuffer.len - 1)
          needsRedraw = true
      of Key.None: discard
      else:
        if key != Key.None:
          let keyChar = chr(int(key))
          if keyChar != '\0':
            inputBuffer.add(keyChar)
            needsRedraw = true

    # --------------------------------------------------
    # 7. Screen rendering
    # --------------------------------------------------
    if needsRedraw:
      tb.clear()
      # Draw borders first (they persist)
      tb.drawRect(0, 0, cols - 1, rows - 1)
      tb.write(2, 0, "[ Nimstr - Nostr TUI ]", illwill.fgYellow)

      if appMode == AppMode.ModeKeyInput:
        tb.write(4, 3, "Welcome to Nimstr!", illwill.fgYellow)
        tb.write(4, 5, "Please enter your Nostr secret key (nsec1...):", illwill.fgWhite)
        tb.drawHorizLine(4, cols - 5, 7)
        
        var maskedKey = ""
        for idx, c in keyInputBuffer:
          if idx < 9: maskedKey.add(c)
          else: maskedKey.add('*')
          
        tb.write(4, 6, "> " & maskedKey, illwill.fgCyan)
        tb.write(4, rows - 3, "Press [Enter] to Save & Start | [Esc] to Cancel", illwill.fgWhite)
        
      else:
        let statusText = if scrollOffset == 0: "[ LIVE - Tracking Latest ]" else: fmt"[ Scroll: {scrollOffset} (Press 'L' to Live) ]"
        let statusColor = if scrollOffset == 0: illwill.fgGreen else: illwill.fgMagenta
        tb.write(cols - 2 - statusText.len, 0, statusText, statusColor)
        
        tb.drawHorizLine(1, cols - 2, rows - 4)
        
        if appMode == AppMode.ModeNormal:
          tb.write(2, rows - 3, "i: Post Message | S: Set nsec | F: JP Filter | K/Up: Scroll Up | J/Down: Scroll Down | L: Live | Q: Quit", illwill.fgWhite)
        else:
          tb.write(2, rows - 3, "TYPE YOUR MESSAGE AND PRESS ENTER TO POST (ESC TO CANCEL)", illwill.fgYellow)

        let prompt = "> "
        tb.write(2, rows - 2, prompt, illwill.fgCyan)
        tb.write(2 + prompt.len, rows - 2, inputBuffer, illwill.fgWhite)

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

            let prefix = fmt"[{displayName}]: "
            let prefixWidth = displayWidth(prefix)
            let maxContentWidth = max(1, cols - 2 - prefixWidth)

            let wrappedLines = wrapText(ev.content, maxContentWidth)

            for lineIdx in 0 .. wrappedLines.high:
              if currentY < timelineTopY: break

              let contentPart = wrappedLines[lineIdx]
              let usedWidth = prefixWidth + displayWidth(contentPart)
              let padWidth = max(0, maxDisplayWidth - usedWidth)
              let padStr = " ".repeat(padWidth)

              if lineIdx == 0:
                # Display name in cyan, content in white
                writeLine(tb, 1, currentY, prefix, illwill.fgCyan)
                writeLine(tb, 1 + prefixWidth, currentY, contentPart & padStr, illwill.fgWhite)
              else:
                # Continuation line: indent + content (all white)
                writeLine(tb, 1, currentY, " ".repeat(prefixWidth) & contentPart & padStr, illwill.fgWhite)

              # Restore right border (column cols-1)
              tb[cols - 1, currentY] = borderChar

              currentY -= 1

            # Separator line between posts (panel divider)
            if currentY >= timelineTopY:
              tb.drawHorizLine(1, cols - 2, currentY)
              tb[cols - 1, currentY] = borderChar
              currentY -= 1

      tb.display()
      
      if appMode == AppMode.ModeInput:
        setCursorPos(2 + 2 + inputBuffer.len, rows - 2)
      elif appMode == AppMode.ModeKeyInput:
        setCursorPos(4 + 2 + keyInputBuffer.len, 6)
        
      needsRedraw = false

    await sleepAsync(20)

waitFor main()