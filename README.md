# BunnieHop Helper

**License: AGPL-3.0-or-later.** This app is BunnieHop's fork of [youtube-dl-gui](https://github.com/jely2002/youtube-dl-gui) (PLAN D4), based on commit `c402ee39c0eabab68934c48f8b787ff37a1577b0` and `patches/youtube-dl-gui-fixes.patch` at the repo root, brought in without upstream history (`docs/decisions.md` D-002). It is the only AGPL component in this repo; everything else is MIT and clean-room. The tree holds the AGPL text (`LICENSE`) and names the upstream author in `Cargo.toml`, but carries no upstream copyright notice. `src/ytdlp.rs` follows upstream's yt-dlp runner (progress template, line splitting). Whether any upstream source was copied, and so whether its copyright notice must be restored, is open in `docs/backlog.md`.

## Build and run

```sh
cargo run            # debug build: also accepts the local web dev server origins
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

`BUNNIEHOP_DATA_DIR` and `BUNNIEHOP_VAULT_DIR` override the default state folder and vault (`~/BunnieHop`). The HTTP contract is `docs/helper-api.md`.

## Running a release build

Download from https://get.bunniehop.party, unpack, and run `bunniehop-helper` (macOS: right-click → Open the first time, since the build isn't notarised yet; Windows: "More info → Run anyway"). It listens on `127.0.0.1:17333–17340` and opens a local page with the pairing code when you pair from bunniehop.party → Settings. Leave it running while you hop; close the window (or Ctrl-C) to stop it.

Releases are built by `.github/workflows/release.yml` on a `helper-v*` tag. Each archive has a `.sha256` next to it.

Status: v0.1. Done: localhost server on `127.0.0.1:17333` with Origin and Host guards (pairing origin `https://bunniehop.party` only), pairing through a local code page with rate limits, yt-dlp catalog and downloads with checksum-verified tool installs, local vault with `bunniehop.json` + `index.csv`, Dropbox and Google Drive vaults (D-041, D-046), hop queue with pacing and daily caps, hops that resume after a Helper restart (D-039), a posted ledger so an item never goes to the same account twice across hops (D-048), export zips, keychain connections, and uploaders for YouTube (D-045), Bluesky, Mastodon, Pixelfed, PeerTube, LinkedIn (D-040), Discord, Ghost and WordPress. A Telegram uploader exists but is unregistered (D-043), and SigV4 signing for the S3 vault (O-004) is written but not wired into hops. Next: S3 and Internet Archive vaults, Vimeo, Dailymotion and Tumblr uploaders, video edits (the Helper reports `canTransform: false` until they run, D-051), tray shell and signed installers.
