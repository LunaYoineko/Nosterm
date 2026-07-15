# Package

version       = "0.1.0"
author        = "LunaYoineko"
description   = "Nostr TUI client in Nim"
license       = "MIT"
srcDir        = "src"
bin           = @["nimstr_tui"]


# Dependencies

requires "nim >= 2.2.10"
requires "ws"
requires "illwill"
requires "secp256k1"
requires "nimSHA2"

switch("define", "ssl")