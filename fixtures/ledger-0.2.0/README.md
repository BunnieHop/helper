# Helper 0.2.0 posted ledger

What a creator's `hops/` folder holds after Helper 0.2.0 ran. `helper_0_2_0_ledger_never_reposts_after_grouping` (`src/hops.rs`) loads it, then groups the videos and hops all four. Nothing here may be edited by hand. A change means a new capture from the same commit.

Written by 0.2.0's own `Posted`, `UploadHandles` and `uploaders::bluesky::tid_for` at commit `cf462800ddbf3332145478dba422908affbfddf7`, in a scratch worktree with one test module added that only calls them. At that commit, `src/posted.rs`, `src/hops.rs`, `src/uploaders/bluesky.rs` and `src/uploaders/mastodon.rs` are byte-identical to the public tag `helper-v0.2.0` (`aa4e762e99c58e6c6f5533c3c8171bd2383cb308`), and `Cargo.toml` says version 0.2.0.

- `hops/posted.json`:
  - `bluesky|bluesky-1|youtube|a`: published.
  - `facebook|facebook-1|youtube|a`: reserved, cut off mid-upload.
  - `bluesky|bluesky-1|youtube|c`: reserved, cut off.
- `hops/upload-handles/`: Facebook's upload marker for item a.
- `expected.json`: the keys, item c's original date, both Bluesky record keys 0.2.0 derives, and the marker's file name.

The handle, ids and session are invented (O-002).
