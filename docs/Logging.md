# Structured logging and the text log

The proxy writes **one record per event** and renders the text you read on the console from those same
records. There is one pipeline and two consumers: the segment files on disk (`--log-dir`) and the text
log (`--text-log`). The text is a *projection* of the records, not a second stream that happens to
describe the same connection — which is what makes "the console said X but the file says Y" impossible
rather than unlikely.

The records exist for the one thing a text line cannot do: answer *why* a connection took the path it
took. The console prints the decision the ladder made; the record carries the decision *and* its
inputs — which rung was dialled, what class of failure ended it, how long it took, which cooldown that
armed, what the pool had ready, and how the session closed. The segment is also the part you can count,
grep and diff between two runs.

Nothing about the record stream requires a disk. Without `--log-dir` the pipeline still runs, the
records reach the text log and the RAM ring, and nothing is written anywhere.

## The four things on the console

| what | where | when |
|---|---|---|
| the startup banner | **stdout** | always, on every start — it carries the secret and the `tg://` links, so it is not a log line and no log setting suppresses it |
| the records, rendered | `--text-log`: `stderr` (default), `stdout`, a file path, or `off` | per record, filtered by `--text-level` |
| `tg-ws-proxy: …` lines | **stderr** | always: the log's own failures (a full disk, a segment another process holds), the startup configuration warnings, the second stop signal, and — at `--text-level debug` — the inbound handshakes that were refused before a session existed |
| other crates' lines (`rustls`, `tungstenite`) | **stderr**, prefixed `tg-ws-proxy: ` | only when `RUST_LOG` asks for them; off by default |

A rendered line looks like this:

```
2026-10-12T11:23:16.612026Z  INFO [192.168.1.60:51719] DC2m WS session closed via kws2.web.telegram.org by client: ↑23.4KB  ↓5.3MB  64.5s
└──────────┬──────────────┘  └─┬─┘ └────────┬────────┘ └──────────────────────────────────────────────────────────────────┘
     ISO-8601 UTC, µs       level (5 cols)  the client         what happened, from the event
```

There is no `target` field: the module a line came from is visible in the message itself (`[pool]`,
`[accept]`, `[upstream]`, or the client's address for anything belonging to a session).

`--check` is the one mode that keeps the text log off whatever the flags say: its report is the product
of the mode and goes to stdout on its own.

```sh
tg-ws-proxy --port 1443 --secret <hex>                 # records rendered to stderr, nothing on disk
tg-ws-proxy --port 1443 --secret <hex> --text-log off  # silent console
tg-ws-proxy --port 1443 --secret <hex> --text-level debug --ring-level debug
```

`--verbose` and `--quiet` still work as hidden aliases for `--text-level debug` and `--text-log off`,
because the Android app and older init scripts pass them; an explicit `--text-log`/`--text-level` wins.

## Turning the segment on

```sh
tg-ws-proxy --port 1443 --secret <hex> --log-dir /tmp/tgws-logs
```

```
  Text log:      stderr (text info, ring info ×512)
  Log sink:      /tmp/tgws-logs (7 days, compression zstd-l1, durability eventual, f2fs)
  Log volume:    ~44 B/record · ~1 record per client connection (~4 at debug)
                 1 000 connections/day ≈ 0.3 MB/week (debug 1.2 MB) · idle ≈ 1 MB/week · zstd-l1 ≈ 2× smaller
```

The banner names the filesystem the directory actually landed on, because that is the difference
between a stick that works and one that has to be re-formatted, and between a log and a slice of RAM.
A directory on `tmpfs` prints a warning: the log lives in RAM and `--log-retention` is the only thing
bounding it.

## The ring, and `SIGUSR1`

The writer keeps the last `--ring-capacity` records in memory (512 by default, 64…4096) at the
`--ring-level` floor. Send the process `SIGUSR1` and it prints what it holds through the text sink:

```sh
kill -USR1 "$(pidof tg-ws-proxy)"
```

```
tg-ws-proxy: ring dump, 37 records
2026-10-12T11:23:16.612026Z  INFO [192.168.1.60:51719] DC2 session opened
2026-10-12T11:23:16.612189Z DEBUG [pool] DC2 WS pool hit (3 left)
…
```

That is what makes a post-mortem possible on a device with no debugger: the router misbehaves, you
signal it, and the last few hundred records are on their way to wherever the text goes. With
`--text-log off` there is nowhere for the dump to go — the ring is a diagnostic for a console, not a
second store.

## Flags

The three consumers filter independently, and a record is built if **any** of them wants it: a `debug`
record the segment keeps is built even when the text view is at `info`, and vice versa.

| Flag | Default | Environment | Meaning |
|---|---|---|---|
| `--text-log <stderr\|stdout\|off\|PATH>` | `stderr` | `TG_TEXT_LOG` | Where the rendered text goes. A path is appended to, never truncated; anything that is not `off`/`stderr`/`stdout` is a path |
| `--text-level <LEVEL>` | `info` | `TG_TEXT_LEVEL` | Floor for the text log |
| `--ring-level <LEVEL>` | `info` | `TG_RING_LEVEL` | Floor for the RAM ring behind `SIGUSR1` |
| `--ring-capacity <N>` | `512` | `TG_RING_CAPACITY` | Records the ring holds (64…4096). The build-time default is `TG_TEXT_RING=<N> cargo build` |
| `--log-dir <PATH>` | off | `TG_LOG_DIR` | Directory for the day segments. Unset keeps the records in memory only; the directory is created when missing |
| `--log-level <LEVEL>` | `info` | `TG_LOG_LEVEL` | Floor for the segment, per category |
| `--log-category <CAT,LEVEL>` | — | `TG_LOG_CATEGORY` | Per-category exception to `--log-level`, repeatable; the env value joins several with `+` |
| `--log-retention <DAYS>` | `7` | `TG_LOG_RETENTION` | Segments to keep, counting today; `0` keeps every segment. Enforced by file name at rotation |
| `--log-compress <MODE>` | `none` | `TG_LOG_COMPRESS` | `none` or `zstd-l1`; the latter needs a build with `--features log-zstd` |
| `--log-durability <MODE>` | `eventual` | `TG_LOG_DURABILITY` | `eventual` syncs every 30 s, `immediate` syncs before every flush returns |
| `--log-flush-interval <SEC>` | `2` | `TG_LOG_FLUSH_INTERVAL` | How long a record may sit unwritten before a flush — the window a process that dies takes with it. It is *not* the power-cut window: that one is `--log-durability` |
| `--log-batch-max <N>` | `256` | `TG_LOG_BATCH_MAX` | Records buffered before a flush is forced (16…4096) |
| `--log-flush-on-warn` | off | `TG_LOG_FLUSH_ON_WARN` | Flush as soon as a warning or an error is recorded |
| `--verbose` / `-v` | off | `TG_VERBOSE` | Legacy alias for `--text-level debug` |
| `--quiet` / `-q` | off | `TG_QUIET` | Legacy alias for `--text-log off`; the banner is not affected |

The text log has no per-category exceptions: it is read by a person watching a terminal, not queried.
`--log-category` is the segment's alone.

## What gets recorded

| Event | Level | Category | Answers |
|---|---|---|---|
| `startup_summary` | info | config | what this process was started with: version, listen address, `--dc-ip` targets, effective tier order, effective per-category levels |
| `session_opened` | info | session | a client handshake finished — DC, media class, peer |
| `session_closed` | info | session | how the session ended: tier that carried it, who closed it, bytes each way, duration. `warn` when nothing could carry it (`no_route`) |
| `tier_attempt` | info (ok) / warn (failed) | routing | one rung was dialled — tier, DC, host it ended on, ok/fail, duration, failure class and `errno` |
| `tls_handshake` | debug | tls | the handshake behind a dial: full or resumed, and how long |
| `tier_fallback` | info | routing | the ladder stepped down: from which rung to which, and why |
| `attempt_skipped` | debug | routing | a rung the ladder never dialled, and the reason |
| `cooldown_armed` | warn | cooldown | a failure memory was set: kind, key (DC, IP, domain), duration |
| `cooldown_cleared` | debug | cooldown | the memory expired or was dropped |
| `cooldown_skipped` | debug | cooldown | a rung was not even tried because of an armed cooldown |
| `pool_hit` / `pool_miss` | debug | pool | a client took a pre-warmed connection, or had to dial |
| `pool_refill` | debug | pool | background refill: how many were added, how many are ready, in what time, and the failure when it could not connect |
| `pool_discard` | debug | pool | a pooled connection was thrown away, and why (`stale`, `closed`) |
| `warmup_complete` | debug | pool | the startup warm-up finished: how many connections are ready |
| `relay_init_retries` | warn | crypto | retries when the relay's first frame did not decode |
| `accept_error` | warn | accept | an inbound connection was rejected: errno, backoff |
| `probe_result` | info | check | a `--check` probe finished: kind, target, ok/fail, duration, failure class |
| `domain_list_fetched` | info / warn | config | where `--default-domains` got its list; `warn` when the built-in fallback is what runs |
| `fd_snapshot` | debug | accept | descriptor budget: open, soft limit, permits available |
| `shutdown` | info | config | the stop was asked for (with the signal) and it completed |
| `log_overflow` | warn | overflow | records dropped because the writer could not keep up, and over what window |

Levels are a floor, not a ceiling, and they belong to the *event*, not to the caller: a successful dial
is `info` whatever rung made it, a failed one is `warn`. `--log-level warn` keeps warnings and errors
and drops the rest, and `--log-category routing,debug` raises one category back up. The line that
matters most in practice is `info` against `debug`: at `info` a healthy connection leaves one record
(`session_closed`) and a broken one leaves the whole walk, because every failure is `warn`.

## What the rework buys you, measured

One scenario, both binaries: six synthetic clients speaking the real obfuscated handshake (DC 2 and DC 4,
ordinary and media classes), each held for a few seconds, the ladder allowed to finish. It is a scenario
rather than a network, so the claim it supports is about the *format* of the output rather than about
anyone's traffic.

| | upstream 2.5.4, `--verbose` | this build, `--text-level info` |
|---|---|---|
| lines in the file for the run | 254 | 18 before the `SIGUSR1` below, 39 after it |
| of them other crates' internals | 144 (57 %) | 0 |
| lines about the pool | 10 — `pool hit` and `failed to pre-connect` only | 0 in the file, 14 records in the segment |
| how a session ends | `DC4m WS session closed by upstream: ↑1.0KB  ↓8.0B  0.1s` — `WS` whatever the rung, and no host | `DC2m WS session closed via kws2-1.web.telegram.org by upstream: …` |

Those 18 lines are the whole operator-facing story at that level: six `session opened`, six `WS connected
via …`, six `session closed …`. Everything else the run produced — `pool_refill`, `pool_miss`,
`tls_handshake`, `tier_attempt`, `warmup_complete`, `startup_summary` — is 42 records in the segment, and
reaches the file only when asked for: raise `--text-level`, or leave the ring at `debug` and send
`SIGUSR1` — in that run the dump appended 39 lines to the same file, out of 40 records kept (one of them,
`startup_summary`, renders no line).

2.5.4's dependency noise is avoidable there with `RUST_LOG=tg_ws_proxy_rs=debug`; here it is not possible
in the first place, because the record stream never goes through `tracing` — with `RUST_LOG=debug` the
text file and the segment gain nothing (the console gains `rustls` lines, as the table on the first page
says).

**The text rounds, the record does not.** Both formats print a size in a human unit with one decimal
(`516.0B`, `2.0KB`, `5.3MB`), so the file is not a source for "how much went through": summing `↑`/`↓`
over the run above gives 20 480 B up, while the `bytes_up` fields of the same six `session_closed`
records sum to 20 504 B. The gap is the rounding, and it grows with the number: a line that reads
`↓11.3MB` is not a byte count.

What that is worth on a real device, from a 2.5-minute window on the reference router during a CF Worker
outage — all of it counted out of one segment, none of it available from the text log:

```
cfworker   44 attempts,  6 failed (14 %)   p50 268 ms, p95 10 085 ms   — every failure TlsTimeout
cfproxy     9 attempts,  0 failed          p50 339 ms, p95  1 075 ms
6 × cooldown armed for the worker (60 s each), 4 × a rung skipped because of one
34 sessions, 26 835 B up, 1 549 250 B down, p50 15.4 s, max 104.8 s, 39/20/5 sessions per client
```

In 2.5.4 the close line says `WS` for anything that went over a WebSocket — Cloudflare Worker and
CF-proxy sessions included — and names the host only on the connect line, so which rung carried a
session cannot be read off its end. The pool's misses and refills are not printed at any level, and every
size is rounded: the same questions have no answer there, however long the file is.

The price of that is stated once, below: the exact numbers live in the segment, and reading a segment
means the repository's test reader. The text log is what you read on the device; the segment is what you
count.

## Reading a segment back

There is **no CLI reader** in the binary, deliberately: reading a segment is a post-mortem operation,
not something the proxy needs at runtime, and the reader that ships with the repository is enough to
get a record-for-record dump:

```sh
TG_DUMP_DIR=/tmp/tgws-logs TG_DUMP_DATE=2026-10-11 \
  cargo test --features log-zstd --lib dump_segment -- --ignored --nocapture
```

```
batch ts=1791735882145978319 records=33 conns=[0, 1, 2, …]
  seq=1 conn=0 level=2 category=9 Some(StartupSummary(StartupSummary { version: "2.5.4-struct-logging", …
  seq=2 conn=2 level=1 category=1 Some(SessionOpened(SessionOpened { peer: Some(Peer { addr: [192, 168, …
```

A segment written with `zstd-l1` needs a build that has the codec, so keep the `log-zstd` feature in
the same configuration as the binary that wrote it. Field numbers, event tags and the on-disk format
are fixed by `src/log/schema.rs`; a later binary reads an older segment. A segment written under a
different schema version is refused at startup rather than appended to, and the message names both
hashes — move the old day files aside and restart.

Refusing is not the same as leaving the file alone: the check runs after `redb` has opened it, and about
2 % of a 500 KB segment's bytes differed afterwards — from offset 10, which is the database header, down
into the pages. The reader opens the file the same way, so reading a copy is not a promise that the copy
is untouched, which matters when the copy is the only one and it lives on flash.

## Clocks, runs and connection ids

Three facts about a router that the log cannot fix, only record:

- **There is no RTC.** A freshly booted OpenWrt router sets the clock from the newest file in `/etc`
  and `ntpd` corrects it a couple of minutes later — by minutes, sometimes by hours (measured on the
  reference router: +4 h 55 m, and +8 h 18 m the day before). Records carry wall-clock time, so the
  jump is visible as timestamps that leap forward or back while `seq` keeps counting: the sequence is
  monotonic, the clock is not. A record written before the correction is not wrong; it is written in
  the clock of that moment, and the run's first records can land in the previous day's file.
- **Two runs in one day file are not distinguishable by the file.** `conn_id` numbers sessions from
  one at every start, so `conn_id = 7` exists in both. `startup_summary` is what separates them: it is
  written once per run, and the text view uses it to forget the client addresses of the previous run.
- **The text log is the run's own record.** It is appended to across restarts, so give each run its own
  file (the install script rotates the previous one to `.log.1`) or grep for the `startup_summary`
  line's time before reading the rest.

## Where to put the directory

The sink needs a filesystem it can trust with a lock-protected database, and it says so at startup
rather than corrupting a segment later: `--log-dir` on a FAT-family mount is refused with
`ErrorCode::FsUnsupported` before anything is opened.

| Filesystem | Verdict | Why |
|---|---|---|
| `ext4`, `xfs`, `btrfs`, `f2fs`, `tmpfs`, `overlayfs`, `ubifs` | accepted | journalled or log-structured; POSIX locks and `fsync` behave |
| `vfat`, `msdos`, `umsdos`, `exfat`, `ntfs`, `ntfs3`, `fuseblk`, `hpfs` | **refused at startup** | a support decision, not a kernel limitation: the database's locking and durability on those mounts is untested here, and "very probably" is not a promise to make about the one file that holds every session's metadata. The message names the fix — `mkfs.f2fs` on the stick, or `--log-dir` on `tmpfs` |
| anything unrecognised | accepted, with a warning | a filesystem this code has never heard of is more likely a new Linux one than a FAT variant |

Practical choices, from cheap to durable:

- **`tmpfs`** — free, fast, no flash wear, gone at reboot. The right default on a router that has RAM
  to spare and a collector that copies the segment out, and the banner warns that `--log-retention` is
  the only thing bounding it.
- **A USB stick formatted `f2fs` or `ext4`** — survives reboots and keeps the router's own flash
  untouched. f2fs is built for NAND and for power cuts; format it once and mount it with `noatime`.
- **The router's own flash (`ubifs`/`overlayfs`)** — works, but every record is a write to the same
  NAND the firmware lives on. If the segment is needed there, keep `--log-retention` small.

## What it costs

Binary size, measured on this build's release profile (`lto`, `codegen-units = 1`, `strip`), with the
musl targets built against a musl cross toolchain:

| Target | upstream 2.5.4 | default | `--features log-zstd` |
|---|---|---|---|
| `x86_64-unknown-linux-musl` | 4 616 896 B | 5 728 448 B (**+24 %**) | 6 277 312 B (+36 %) |
| `aarch64-unknown-linux-musl` | 3 862 600 B | 4 773 464 B (**+24 %**) | 5 228 120 B (+35 %) |

Both ends of a row come from the same profile and the same toolchain, and that matters: the same source
built for `x86_64-unknown-linux-gnu` is ~135 KB smaller than its musl twin, so a gnu baseline against a
musl build overstates the increase by about four points. The zstd codec adds another 536 KiB on
x86-64 and 444 KiB on aarch64. The release workflow builds `log-zstd` in for the musl targets (aarch64,
x86_64), the Apple targets (both architectures and the universal build) and `x86_64-pc-windows-gnu`;
the armv7 and MIPS targets ship without it, and `--log-compress` there offers `none` alone. A build
without the codec cannot read a
compressed segment.

Volume, measured rather than estimated: a record is **~44 B**, a client connection writes about **one**
of them at the default level and about **four** at `--log-level debug`, and an idle process writes the
descriptor snapshot once a minute. 1 000 connections/day is ≈ 0.3 MB/week at `info` (1.2 MB at
`debug`), idle is ≈ 1 MB/week, and `zstd-l1` roughly halves both. A 4 GB stick therefore holds years of
`info`-level traffic; `--log-retention 7` is what actually bounds it.

**Those are the record bytes, not what the medium sees.** A flush window that carries at least one
record ends in one `redb` commit, and a commit dirties pages: on the reference router (OpenWrt,
aarch64, USB stick on f2fs, `debug`, `zstd-l1`) a seven-minute window with **51 commits, 328 records
and 98 client sessions** cost the device **916 KiB** — about **18 KB per commit** — while the record
payload in the same stretch was ~25 B/s. An idle proxy commits nothing at all (`flush` returns early on
an empty buffer), so the cost follows the number of *active* windows rather than the number of records,
and the lever is `--log-flush-interval`: a longer interval means fewer, fuller commits and a larger
crash window, which is the same trade as durability. At that traffic level the extrapolated cost is
≈ 180 MB/day of flash traffic — a 4 GB stick's worth of writes every few weeks, well inside what the
medium is rated for, but two hundred times what the text log writes.

On that same router the day file held **1 268 records for 166 sessions** in its first nine minutes, i.e.
**4.1 records per session** — the number the level estimate predicted.

## Durability and power cuts

There are two windows, and they are set by two different things. A record first waits in the writer's
memory for at most `--log-flush-interval` (2 s by default) before it is committed to the segment file;
the commit reaches the medium only when the durability mode syncs it. So:

- a **process that dies** — `kill -9`, the OOM killer, a watchdog — takes the unflushed window with it:
  at most `--log-flush-interval`, and nothing more, because everything already committed is in the
  kernel's page cache and the filesystem survives the process;
- a **power cut or a kernel panic** takes everything that was committed but never synced: at most the
  sync interval, which is **30 s** under `eventual` and effectively nothing under `immediate`;
- a **clean stop** (`SIGTERM`, `service stop`) is complete in both modes: the writer is drained and the
  segment is synced before the process exits.

| What happens | `eventual` (default) | `immediate` |
|---|---|---|
| clean `SIGTERM` | complete — measured 7 of 7 records kept | complete |
| process dies (`kill -9`) | the flush window — measured **0** records with a 30 s window; a 2 s window costs at most 2 s | the flush window — this mode changes nothing here |
| power cut, kernel panic | the sync interval — **≤ 30 s** | nothing that was written |
| cost | 2 880 fsyncs a day | one fsync per flush — 43 200 a day at the default interval, which is real wear on a cheap stick |

`immediate` is the choice when the log is evidence rather than diagnostics and the medium can take the
writes; `eventual` is the default because a router's flash pays for every `fsync`.
`--log-flush-on-warn` is the middle ground: warnings and errors go out at once, the rest waits.

The **text** log has no such window: it is written line by line as it is rendered, and a power cut costs
the line that was being written. That is the trade for having no second buffer to lose — and the reason
a text line can never be the evidence a segment is.

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

The same is true of a text log written to a file: `--text-log /var/log/tg-ws-proxy.log` needs that
directory staged too (`-w /var/log`), and the file has to be creatable inside the jail.

Two details that cost time to learn:

1. **The jail has no external commands.** Only the staged paths exist inside it, so busybox is not
   there: a wrapper that calls `cat`, `grep` or `sed` dies with exit 127, and procd turns that into a
   crash loop. Read files with shell builtins (`read -r var < file`).
2. **`ujail` does not forward the stop signal to the jailed child**, so a stop that only signals the
   jail leaves the proxy holding its port. Signal the child too — and with this build the child then
   exits by itself (`SIGTERM` is handled, the sink is drained), where 2.5.0 was killed by it. Measured
   on the reference router: a stop took **4 s** with 2.5.0 (three of them waiting before `kill -9`) and
   **1 s** with this build.

A missing or failed stick should cost the log, not the service: resolve the directory in the init
script, fall back to `tmpfs` when the mount is absent, and hand the decision to the wrapper (for
example in a file under the staged runtime directory).

**The packaged LuCI app does none of the above for you.** Its only logging control is the
`log_level` selector, which sets the text view's floor; neither `--log-dir`/`TG_LOG_DIR` nor
`--text-log` is exposed, so an operator who wants segments or a text file edits the init script as
shown here. See [OpenWrtPackage.md](OpenWrtPackage.md).

## Known gaps

- No CLI reader, as above — reading means the repository's test reader.
- The midnight rollover (closing one day's segment and opening the next) is covered by unit tests; the
  retention sweep that deletes older segments is covered by unit tests *and* was verified on the
  reference router by seeding two dated segments and restarting.
- **The Android app's on-screen log is behind this rework.** Its Log panel and logcat are fed by the
  `tracing` layer, which now carries only other crates' lines, so the panel shows nothing of the
  proxy's own. The app still starts, parses its arguments and shows the `tg://` link (that arrives
  through the listen callback, not by scraping the log); the panel needs its own consumer for the
  record stream.
