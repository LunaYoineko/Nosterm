# AGENTS.md — Nosterm

このリポジトリで作業するエージェント（および人間）向けのガイドです。

## これは何か

Nosterm は Nim で書かれた Nostr の TUI クライアントです（単一のメインモジュール
`src/Nosterm.nim`）。WebSocket リレー経由で kind 0（プロフィール）と kind 1
（ノート）を購読し、スクロール可能なタイムラインを描画します。投稿、リレーの
管理、@メンションに対応します。ビルド／設定は `Nosterm.nimble`。

## ビルドと実行

```sh
nimble build      # -> ./Nosterm
nimble run        # ビルドして起動
```

nimble ファイルで `switch("define", "ssl")` が有効です（`wss://` に必要）。
Nim >= 2.2.10。この `ssl` スイッチを削除してはいけません。

## 描画に関する重要な制約（触る前に読む）

**`tb.display()` を呼んではいけません。`setDoubleBuffering` も有効にしないで
ください。**

`illwill` 0.4.1 はワイド文字（全角文字）に未対応です。その `write` は1ルーンを
1セルに書き込み、差分描画は「1セル == 1ターミナル列」とみなします。全角ルーンは
2列を占めるため、illwill のカーソル管理がズレて画面が崩れます。そのため、自前の
描画関数 `renderToTerminal`（`src/Nosterm.nim`、約 101 行目）を illwill の
display の代わりに使っています。

- `writeLine(tb, x, y, text, color)` は全角ルーンをセル `cx` に、`NUL プレース
  ホルダ`（`Rune(0)`）を `cx+1` に書きます。`renderToTerminal` はプレースホルダを
  飛ばしてグリフを出力します。
- `isWideRune(r)` が幅を決めます。**罫線文字（`│`、`─` など、ord >= 0x2500）は
  半角（1列）**であり、全角として扱ってはいけません。East Asian Wide の範囲のみ
  を全角とします。`isWideRune` と `writeLine` の整合を保ってください。
- `renderToTerminal` は各行を1つの ANSI 行（`\e[Y;1H…`）として出力し、内容が
  変化した行だけを書き直します（`prevScreen` との行単位差分）。これがちらつきを
  防ぎます。セルモデルと行出力の整合を常に保ち、末尾のセルはスペースで埋めて
  古い内容が残らないようにしてください。

新しい画面出力を追加するときは `TerminalBuffer`（`tb`）を経由し、
`renderToTerminal` に描画させてください。`setTermCursor` / `showTermCursor` /
`hideTermCursor` 以外で直接 ANSI を stdout に書かないでください。

## 入力

`illwill` の `getKey` は1バイトずつ読むため、マルチバイト UTF-8（日本語）が
壊れます。その代わり、生リーダ（`nextRune` / `drainStdin`）が `posix` の
`poll`/`read`（fd 0）を使って完全なルーンを組み立てます。ターミナルのエスケープ
シーケンスから来る矢印キーはセンチネルルーン `RuneUp`/`RuneDown`/`RuneLeft`/
`RuneRight`（0xEE01–0xEE04）に変換されます。これらは入力ハンドラで明示的に
無視／処理してください。

モード（`AppMode` 列挙）：`ModeNormal`、`ModeInput`、`ModeKeyInput`、
`ModeMention`、`ModeRelay`、`ModeRelayAdd`、`ModeRelayPick`。メインループは
モードで分岐します。テキスト入力モードは生ルーンリーダを、それ以外は
`illwill.getKeyWithTimeout` を使います。

## Nostr 固有の仕様

- 署名：Schnorr（`secp256k1`）。イベント ID と署名の hex は**小文字**で送信
  すること（リレーは大文字小文字を区別して比較する。過去に大文字の ID が
  "invalid event" と弾かれたバグがありました）。
- `sendNostrPost` は `["client", "Nosterm"]` タグを付与します。タイムラインは
  任意の `client` タグを表示し、Nosterm のみ緑色（大文字小文字区別なし）で描画
  します。
- 内容が空のノートは `insertEvent` で破棄されます（スパム対策）。
- `displayContent` は `nostr:npub1…` トークンを表示用に `@表示名` に書き戻します。
  実際の投稿は正規の `nostr:npub1…` 形式を保ちます。
- bech32 のエンコード／デコードはゼロから実装しています（既知の鍵の正規 `npub`
  と一致すること確認済み）。両方向の整合を保ってください。

## リレー

- `relayConfigs`（永続化される設定）と `relayConns`（稼働中の WebSocket 接続）は
  別物です。
- リレーごとに受信タスク `relayRecv` が1つ動きます。`relayGen` は世代カウンタで
  `applyRelayConfig()` のたびに増加し、古いタスクは不一致を検知して終了するため、
  再設定が安全です。
- `sendToRelays` は `write` フラグ付きリレーへブロードキャストし、
  `requestProfiles` は `read` フラグ付きリレーへ問い合わせます。
- アカウントのリレー取得は**手動**です。リレー管理画面で `f` を押すと kind 10002
  を取得して選択画面を出します。自動取得はありません。

## 設定

`~/.nosterm_config`（JSON: `{nsec, relays:[{url,read,write}]}`、パーミッション
`600`）。`nsec` だけを書いた旧形式ファイルは自動マイグレーションされます。
`loadConfig` / `saveConfig` / `applyNsec` が管理します。`nsec` をログ出力したり
コミットしたりしてはいけません。

設定が空の場合のデフォルトリレーは `wss://yabu.me`（`read: true, write: true`）です。

## `src/Nosterm.nim` の構成（目安）

- 幅／描画ヘルパ： `isWideRune`、`runeWidth`、`displayWidth`、`fitToWidth`、
  `writeLine`、`renderToTerminal`、カーソルヘルパ。
- メンション： `mentionMap`、`mentionList`、`mentionSel`、`mentionAnchor`、
  `refreshMentionFilter`、`handleMentionRune`。
- リレー： `RelayConfig`/`RelayConn`、`relayConfigs`/`relayConns`/`relayGen`、
  `applyRelayConfig`、`relayRecv`、`sendToRelays`、`collectAccountRelay`、
  `fetchAccountRelays`。
- Nostr： `sendNostrPost`、`insertEvent`、`processPacket`、bech32 ヘルパ。

## 注意事項／慣習

- スタイル：指示がない限りコメントは追加しないでください。
- 変更は最小限にとどめ、既存のパターン（グローバル変数 ＋ async タスク）に
  従ってください。
- 編集後は `nimble build` でコンパイルを確認してください。
- `Nosterm.nim.bak` は古いバックアップです。ソースとして扱わないでください。
