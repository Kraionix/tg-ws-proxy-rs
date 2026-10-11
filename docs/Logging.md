# Structured logging

`--log-dir` turns on a second log sink beside the console and `--log-file`: instead of text lines,
the proxy writes one record per event, batched and stored in **one segment file per UTC day**. The
text log still works exactly as before — the structured sink is additional, never a replacement,
and nothing about it exists until `--log-dir` is set.

The reason it exists is the one thing the text log cannot do: answer *why* a connection took the
path it took. The console prints the decision the ladder made; the segment carries the decision
*and* its inputs — which rung was dialled, what class of failure ended it, how long it took, which
cooldown that armed, what the pool had ready, and how the session closed.

## Turning it on

```sh
tg-ws-proxy --port 1443 --secret <hex> --log-dir /tmp/tgws-logs
```

```
  Listening on   192.168.1.1:1443
  Log sink:      /tmp/tgws-logs (7 days, compression zstd-l1, durability eventual, f2fs)
  Log volume:    ~44 B/record · ~1 record per client connection (~4 at debug)
                 1 000 connections/day ≈ 0.3 MB/week (debug 1.2 MB) · idle ≈ 1 MB/week · zstd-l1 ≈ 2× smaller
```

The banner names the filesystem the directory actually landed on, because that is the difference
between a stick that works and one that has to be re-formatted, and between a log and a slice of
RAM. A directory on `tmpfs` prints a warning: the log lives in RAM and `--log-retention` is the only
thing bounding it.

## What gets recorded

| Event | Level | Category | Answers |
|---|---|---|---|
| `startup_summary` | info | config | what this process was started with: version, listen address, `--dc-ip` targets, effective tier order, effective per-category levels |
| `session_opened` | debug | session | a client handshake finished — DC, media class, peer |
| `session_closed` | info | session | how the session ended: tier that carried it, who closed it, bytes each way, duration |
| `tier_attempt` | debug | routing | one rung was dialled — tier, DC, ok/fail, duration, failure class |
| `tier_fallback` | info | routing | the ladder stepped down: from which rung to which, and why |
| `cooldown_armed` | info | cooldown | a failure memory was set: kind, key (DC, IP, domain), duration |
| `cooldown_cleared` | debug | cooldown | the memory was dropped |
| `cooldown_skipped` | debug | cooldown | a rung was not even tried because of an armed cooldown |
| `pool_hit` / `pool_miss` | debug | pool | a client took a pre-warmed connection, or had to dial |
| `pool_refill` | debug | pool | background refill: how many connections were added, in what time, on which tier |
| `tls_handshake` | debug | tls | TLS variant (full/resumed) and duration |
| `relay_init_retries` | debug | crypto | retries when the relay's initial frame did not decode |
| `accept_error` | warn | accept | an inbound connection was rejected: errno, backoff |
| `probe_result` | info | check | a `--check` probe finished: kind, target, ok/fail, duration, failure class |
| `fd_snapshot` | debug | accept | descriptor budget: open, soft limit, permits available |
| `log_overflow` | warn | overflow | records dropped because the writer could not keep up, and over what window |

Levels are a floor, not a ceiling: `--log-level warn` keeps warnings and errors and drops the rest,
and `--log-category routing,debug` raises one category back up. The level that matters most in
practice is the difference between `info` and `debug`: at `info` a healthy connection leaves one
record (`session_closed`), and the ladder's per-rung decisions — `session_opened`, `tier_attempt`,
`pool_*` — are `debug`. Failures are visible either way: `tier_fallback` and `cooldown_armed` are
`info`.

## Flags

| Flag | Default | Environment | Meaning |
|---|---|---|---|
| `--log-dir <PATH>` | off | `TG_LOG_DIR` | Directory for the day segments. Unset disables the sink completely; the directory is created when missing |
| `--log-level <LEVEL>` | `info` | `TG_LOG_LEVEL` | Floor for every category (`debug`, `info`, `warn`, `error`) |
| `--log-category <CAT,LEVEL>` | — | `TG_LOG_CATEGORY` | Per-category exception, repeatable; env value joins several with `+` |
| `--log-retention <DAYS>` | `7` | `TG_LOG_RETENTION` | Segments to keep, counting today; `0` keeps every segment. Enforced by file name at startup |
| `--log-compress <MODE>` | `none` | `TG_LOG_COMPRESS` | `none` or `zstd-l1`; the latter needs a build with `--features log-zstd` |
| `--log-durability <MODE>` | `eventual` | `TG_LOG_DURABILITY` | `eventual` syncs every 30 s, `immediate` syncs before every flush returns |
| `--log-flush-interval <SEC>` | `2` | `TG_LOG_FLUSH_INTERVAL` | How long a record may sit unwritten before a flush — the window a process that dies takes with it. It is *not* the power-cut window: that one is `--log-durability` |
| `--log-batch-max <N>` | `256` | `TG_LOG_BATCH_MAX` | Records buffered before a flush is forced (16…4096) |
| `--log-flush-on-warn` | off | `TG_LOG_FLUSH_ON_WARN` | Flush as soon as a warning or an error is recorded |

## Reading a segment back

There is **no CLI reader** in the binary, deliberately: reading a segment is a post-mortem
operation, not something the proxy needs at runtime, and the reader that ships with the repository
is enough to get a record-for-record dump:

```sh
TG_DUMP_DIR=/tmp/tgws-logs TG_DUMP_DATE=2026-10-11 \
  cargo test --features log-zstd --lib dump_segment -- --ignored --nocapture
```

```
batch ts=1791735882145978319 records=33 conns=[0, 1, 2, …]
  seq=1 conn=0 level=2 category=9 Some(StartupSummary(StartupSummary { version: "2.5.4-struct-logging", …
  seq=2 conn=2 level=1 category=1 Some(SessionOpened(SessionOpened { dc: 4, is_media: false, …
```

A segment written with `zstd-l1` needs a build that has the codec, so keep the `log-zstd` feature
in the same configuration as the binary that wrote it. Field numbers, event tags and the on-disk
format are fixed by `src/log/schema.rs`; a later binary reads an older segment.

## Where to put the directory

The sink needs a filesystem that can hold a lock-protected database, and it says so at startup
rather than corrupting a segment later. `--log-dir` on a FAT-family mount is refused with
`ErrorCode::FsUnsupported`.

| Filesystem | Verdict | Why |
|---|---|---|
| `ext4`, `xfs`, `btrfs`, `f2fs`, `tmpfs`, `overlayfs`, `ubifs` | accepted | journalled or log-structured; POSIX locks and `fsync` behave |
| `vfat`, `msdos`, `umsdos`, `exfat`, `ntfs`, `ntfs3`, `fuseblk`, `hpfs` | **refused at startup** | no locking discipline that survives a power cut; the FAT family also cannot hold the file sizes involved |
| anything unrecognised | accepted, with a warning | a filesystem this code has never heard of is more likely a new Linux one than a FAT variant |

Practical choices, from cheap to durable:

- **`tmpfs`** — free, fast, no flash wear, gone at reboot. The right default on a router that has
  RAM to spare and a collector that copies the segment out, and the banner warns that
  `--log-retention` is the only thing bounding it.
- **A USB stick formatted `f2fs` or `ext4`** — survives reboots and keeps the router's own flash
  untouched. f2fs is built for NAND and for power cuts; format it once and mount it with `noatime`.
- **The router's own flash (`ubifs`/`overlayfs`)** — works, but every record is a write to the
  same NAND the firmware lives on. If the segment is needed there, keep `--log-retention` small.

## What it costs

Binary size, measured on this build's release profile:

| Target | default | `--features log-zstd` |
|---|---|---|
| `x86_64-unknown-linux-musl` | 5 646 664 B | 6 200 360 B |
| `aarch64-unknown-linux-musl` | 4 792 928 B | 5 317 216 B |

Against the 4 481 040 B of 2.5.4 that is **+26 %** for the structured sink, and the zstd codec adds
another ~550 KiB. The release workflow builds `log-zstd` in for the musl targets (aarch64, x86_64),
the Apple targets (both architectures and the universal build) and `x86_64-pc-windows-gnu`; the armv7
and MIPS targets ship without it, and `--log-compress` there offers `none` alone. A build without the
codec cannot read a compressed segment.

Volume, measured rather than estimated: a record is **~44 B**, a client connection writes about
**one** of them at the default level and about **four** at `--log-level debug`, and an idle process
writes the descriptor snapshot once a minute. 1 000 connections/day is ≈ 0.3 MB/week at `info`
(1.2 MB at `debug`), idle is ≈ 1 MB/week, and `zstd-l1` roughly halves both. A 4 GB stick therefore
holds years of `info`-level traffic; `--log-retention 7` is what actually bounds it.

**Those are the record bytes, not what the medium sees.** A flush window that carries at least one
record ends in one `redb` commit, and a commit dirties pages: on the reference router (OpenWrt,
aarch64, USB stick on f2fs, `debug`, `zstd-l1`) a seven-minute window with **51 commits, 328 records
and 98 client sessions** cost the device **916 KiB** — about **18 KB per commit** — while the record
payload in the same stretch was ~25 B/s. An idle proxy commits nothing at all (`flush` returns early
on an empty buffer), so the cost follows the number of *active* windows rather than the number of
records, and the lever is `--log-flush-interval`: a longer interval means fewer, fuller commits and a
larger crash window, which is the same trade as durability. At that traffic level the extrapolated
cost is ≈ 180 MB/day of flash traffic — a 4 GB stick's worth of writes every few weeks, well inside
what the medium is rated for, but two hundred times what the text log writes.

On that same router the day file held **1 268 records for 166 sessions** in its first nine minutes,
i.e. **4.1 records per session** — the number the level estimate predicted.

## Durability and power cuts

There are two windows, and they are set by two different things. A record first waits in the
writer's memory for at most `--log-flush-interval` (2 s by default) before it is committed to the
segment file; the commit reaches the medium only when the durability mode syncs it. So:

- a **process that dies** — `kill -9`, the OOM killer, a watchdog — takes the unflushed window with
  it: at most `--log-flush-interval`, and nothing more, because everything already committed is in
  the kernel's page cache and the filesystem survives the process;
- a **power cut or a kernel panic** takes everything that was committed but never synced: at most
  the sync interval, which is **30 s** under `eventual` and effectively nothing under `immediate`;
- a **clean stop** (`SIGTERM`, `service stop`) is complete in both modes: the writer is drained and
  the segment is synced before the process exits.

| What happens | `eventual` (default) | `immediate` |
|---|---|---|
| clean `SIGTERM` | complete — measured 7 of 7 records kept | complete |
| process dies (`kill -9`) | the flush window — measured **0** records with a 30 s window; a 2 s window costs at most 2 s | the flush window — this mode changes nothing here |
| power cut, kernel panic | the sync interval — **≤ 30 s** | nothing that was written |
| cost | 2 880 fsyncs a day | one fsync per flush — 43 200 a day at the default interval, which is real wear on a cheap stick |

`immediate` is the choice when the log is evidence rather than diagnostics and the medium can take
the writes; `eventual` is the default because a router's flash pays for every `fsync`.
`--log-flush-on-warn` is the middle ground: warnings and errors go out at once, the rest waits.

## On an OpenWrt router

The proxy usually runs under `ujail`, which stages a **fixed list of paths** into the jail, so a new
writable directory has to be added to that list, and it has to exist before the jail is built:

```sh
# in start_service(), before procd_open_instance
mkdir -p /mnt/usb/tgws-logs
chown tgproxy:tgproxy /mnt/usb/tgws-logs
chmod 0700 /mnt/usb/tgws-logs
procd_append_param command -w /mnt/usb/tgws-logs
```

Two details that cost time to learn:

1. **The jail has no external commands.** Only the staged paths exist inside it, so busybox is not
   there: a wrapper that calls `cat`, `grep` or `sed` dies with exit 127, and procd turns that into
   a crash loop. Read files with shell builtins (`read -r var < file`).
2. **`ujail` does not forward the stop signal to the jailed child**, so a stop that only signals the
   jail leaves the proxy holding its port. Signal the child too — and with this build the child then exits
   by itself (`SIGTERM` is handled, the sink is drained), where 2.5.0 was killed by it. Measured on
   the reference router: a stop took **4 s** with 2.5.0 (three of them waiting before `kill -9`) and
   **1 s** with this build.

A missing or failed stick should cost the log, not the service: resolve the directory in the init
script, fall back to `tmpfs` when the mount is absent, and hand the decision to the wrapper (for
example in a file under the staged runtime directory).

## Known gaps

- No CLI reader, as above — reading means the repository's test reader.
- The midnight rollover (closing one day's segment and opening the next) is covered by unit tests;
  the retention sweep that deletes older segments is covered by unit tests *and* was verified on the
  reference router by seeding two dated segments and restarting.
