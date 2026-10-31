use super::*;
use crate::config::UpstreamTier;

use clap::Parser;

use crate::crypto::HANDSHAKE_LEN;

#[test]
fn faketls_pending_uses_an_offset_and_releases_its_record() {
    let mut pending = PendingData::from_record(vec![10, 11, 12, 13, 14], 2);
    let original_ptr = pending.data.as_ptr();
    let mut first = [0u8; 2];

    assert_eq!(pending.read(&mut first), Some(2));
    assert_eq!(first, [12, 13]);
    assert_eq!(pending.data.as_ptr(), original_ptr);

    let mut last = [0u8; 2];
    assert_eq!(pending.read(&mut last), Some(1));
    assert_eq!(last[0], 14);
    assert!(pending.data.is_empty());
    assert_eq!(pending.data.capacity(), 0);
    assert_eq!(pending.read(&mut last), None);
}

#[tokio::test]
async fn client_handler_future_stays_compact() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, peer) = listener.accept().await.unwrap();

    let config = Arc::new(
        Config::try_parse_from([
            "tg-ws-proxy",
            "--secret",
            "00112233445566778899aabbccddeeff",
            "--pool-size",
            "0",
            "--no-outbound-proxy",
        ])
        .unwrap(),
    );
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let handler = handle_client_with_runtime(server, peer, config, pool, runtime);
    let future_size = std::mem::size_of_val(&handler);
    eprintln!("per-client future size: {future_size} bytes");

    assert!(
        future_size <= 4 * 1024,
        "the per-client future grew to {future_size} bytes"
    );

    drop(handler);
    drop(client);
}

#[test]
fn balanced_rotates_the_starting_domain() {
    let counter = AtomicUsize::new(0);
    let workers = vec![
        "w1.example.workers.dev".to_string(),
        "w2.example.workers.dev".to_string(),
        "w3.example.workers.dev".to_string(),
    ];

    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w1.example.workers.dev",
            "w2.example.workers.dev",
            "w3.example.workers.dev"
        ]
    );
    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w2.example.workers.dev",
            "w3.example.workers.dev",
            "w1.example.workers.dev"
        ]
    );
    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w3.example.workers.dev",
            "w1.example.workers.dev",
            "w2.example.workers.dev"
        ]
    );
}

#[test]
fn balanced_leaves_short_lists_untouched() {
    let counter = AtomicUsize::new(0);
    let single = vec!["only.example".to_string()];

    assert_eq!(balance_offset(&[], true, &counter), 0);
    assert_eq!(balance_offset(&single, true, &counter), 0);
    // A list that cannot be rotated must not consume a counter tick either.
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn domain_order_borrows_without_cloning() {
    let counter = AtomicUsize::new(0);
    let domains = vec!["a.example".to_string(), "b.example".to_string()];

    let ordered =
        domain_order(&domains, balance_offset(&domains, false, &counter)).collect::<Vec<_>>();
    assert!(std::ptr::eq(ordered[0], domains[0].as_str()));
    assert!(std::ptr::eq(ordered[1], domains[1].as_str()));
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn cooldown_is_tracked_per_key() {
    let cooldowns: CooldownMap<String> = CooldownMap::new();

    assert!(!cooldowns.active("w1.example.workers.dev"));

    cooldowns.set(
        "w1.example.workers.dev".to_string(),
        Duration::from_secs(60),
    );
    assert!(cooldowns.active("w1.example.workers.dev"));
    assert!(!cooldowns.active("w2.example.workers.dev"));

    cooldowns.clear("w1.example.workers.dev");
    assert!(!cooldowns.active("w1.example.workers.dev"));
}

#[test]
fn cooldown_expires_once_the_window_passes() {
    let cooldowns: CooldownMap<(u32, bool)> = CooldownMap::new();

    cooldowns.set((2, false), Duration::ZERO);

    assert!(!cooldowns.active(&(2, false)));
}

#[test]
fn cooldown_keys_include_the_media_flag() {
    let cooldowns: CooldownMap<(u32, bool)> = CooldownMap::new();

    cooldowns.set((2, false), Duration::from_secs(60));

    assert!(cooldowns.active(&(2, false)));
    // The media flag is part of the key — a non-media cooldown must not leak
    // into the media bucket for the same DC.
    assert!(!cooldowns.active(&(2, true)));
}

#[test]
fn upstream_key_joins_host_and_port() {
    assert_eq!(upstream_key("proxy.example", 443), "proxy.example:443");
}

#[tokio::test]
async fn an_aborted_direction_still_reports_the_bytes_it_moved() {
    let bytes_up = Arc::new(StdMutex::new(0));
    let mut bytes_down = 0;
    let upload = tokio::spawn({
        let mut bytes = UploadCounter::new(Arc::clone(&bytes_up));
        async move {
            bytes.add(4096);
            tokio::task::yield_now().await;
        }
    });
    let download = async {
        bytes_down += 1024;
        std::future::pending::<()>().await;
        bytes_down += 999_999;
    };

    let closed_by = join_bridge(upload, download).await;

    assert_eq!((*bytes_up.lock().unwrap(), bytes_down), (4096, 1024));
    // The upload direction ran out first, which means the client stopped.
    assert!(matches!(closed_by, ClosedBy::Client));
}

#[tokio::test]
async fn the_side_that_stops_first_is_the_one_reported() {
    // A session that transfers nothing looks identical whichever side hung
    // up; this is what tells a client-side timeout apart from an upstream
    // that dropped us right after the handshake.
    let upload = tokio::spawn(std::future::pending::<()>());
    let download = async {};
    assert!(matches!(
        join_bridge(upload, download).await,
        ClosedBy::Upstream
    ));

    let upload = tokio::spawn(async {});
    let download = std::future::pending::<()>();
    assert!(matches!(
        join_bridge(upload, download).await,
        ClosedBy::Client
    ));
}

// ─── WebSocket framing ───────────────────────────────────────────────────────

/// Bridge one client payload through `bridge_ws` and report the size of every
/// WebSocket message the upstream received.
///
/// Both ends are plain TCP: the framing decision under test happens above the
/// transport, so wrapping the stream in `MaybeTlsStream::Plain` exercises the
/// same code a real TLS connection would.
async fn upstream_frame_sizes(framing: WsFraming, payload: &[u8]) -> Vec<usize> {
    use tokio::net::TcpListener;
    use tokio_tungstenite::{MaybeTlsStream, accept_async, client_async};

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let sizes = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let mut sizes = Vec::new();

        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Binary(data) => sizes.push(data.len()),
                Message::Close(_) => break,
                _ => {}
            }
        }

        sizes
    });

    let tcp = TcpStream::connect(upstream_addr).await.unwrap();
    let (ws, _) = client_async("ws://127.0.0.1/apiws", MaybeTlsStream::Plain(tcp))
        .await
        .unwrap();

    // The client half of the bridge, driven from this test.
    let clients = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let clients_addr = clients.local_addr().unwrap();
    let mut client = TcpStream::connect(clients_addr).await.unwrap();
    let (server, _) = clients.accept().await.unwrap();
    let (reader, writer) = server.into_split();

    let relay_init = generate_relay_init(ProtoTag::PaddedIntermediate, 2);
    let ciphers = build_connection_ciphers(&[0u8; 48], &[0u8; 32], &relay_init);

    let bridge = tokio::spawn(async move {
        bridge_ws(
            ClientReader::Plain(reader),
            ClientWriter::Plain(writer),
            WsBridgeParams {
                ws,
                framing,
                tier: UpstreamTier::Ws,
                via: "kws2.web.telegram.org".to_string(),
                relay_init,
                ciphers,
                proto: ProtoTag::PaddedIntermediate,
                dc: 2,
                is_media: false,
            },
        )
        .await;
    });

    client.write_all(payload).await.unwrap();
    drop(client);
    bridge.await.unwrap();

    sizes.await.unwrap()
}

#[tokio::test]
async fn a_worker_tunnel_never_emits_an_oversized_frame() {
    // Regression for the upload bug upstream fixed in v1.9.1: packet-aligning
    // a Worker tunnel produces one WebSocket message per MTProto packet, and a
    // media upload's packets run past Cloudflare's 1 MiB message cap, which
    // kills the connection mid-transfer. A tunnel is a raw TCP socket at the
    // far end, so it is chunked by client reads instead — and the relay init
    // still goes out as its own first frame.
    const CF_MESSAGE_CAP: usize = 1024 * 1024;
    let payload = vec![0xA5; 3 * CF_MESSAGE_CAP];

    let sizes = upstream_frame_sizes(WsFraming::Tunnel, &payload).await;

    assert_eq!(sizes.first(), Some(&HANDSHAKE_LEN));
    assert!(
        sizes[1..].iter().all(|size| *size <= CLIENT_READ_BUF_SIZE),
        "a tunnel frame must not exceed one client read: {sizes:?}"
    );
    assert_eq!(
        sizes[1..].iter().sum::<usize>(),
        payload.len(),
        "every byte the client sent has to reach the upstream: {sizes:?}"
    );
}

/// A ladder walk reaches a segment: the dial that failed, and the step down
/// the ladder took because of it.
///
/// The dial target is `127.0.0.1`, where nothing listens on 443: a refused
/// connect, which is the fast and deterministic failure this classification
/// exists to name. The read-back is the point — a record that never leaves the
/// writer's channel looks identical to one that was never emitted.
#[cfg(feature = "log-disk")]
#[tokio::test]
async fn a_ladder_walk_lands_in_the_segment_as_attempts_and_fallbacks() {
    let dir = std::env::temp_dir().join(format!("tgws-tier-attempt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--pool-size",
        "0",
        "--log-dir",
        dir.to_str().expect("a utf-8 temp path"),
        "--log-level",
        "debug",
        "--log-batch-max",
        "16",
        "--log-durability",
        "immediate",
    ])
    .unwrap()
    .with_defaults();

    let handle = crate::log::init(config.log_settings(), config.log_disk())
        .expect("a writable temp dir accepts a segment");
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        std::time::Duration::from_secs(60),
        Arc::clone(&runtime),
    ));
    let route = Route {
        config: &config,
        runtime: &runtime,
        pool: &pool,
        timeouts: Timeouts::from_config(&config),
        dc: 2,
        is_media: false,
        media: media_tag(false),
        dc_idx: 2,
        proto: ProtoTag::PaddedIntermediate,
    };

    const CONN: u64 = 7;
    let ws = crate::log::scope(CONN, Arc::clone(&handle), async {
        route.direct_ws("127.0.0.1").await
    })
    .await;

    assert!(ws.is_none(), "nothing is listening on 127.0.0.1:443");

    // Then a whole walk with no `--dc-ip` target: the direct WebSocket rung is
    // unreachable, nothing else is configured, so the ladder falls to TCP —
    // which dials nothing here, so the attempt count must stay at one.
    let upstream = crate::log::scope(CONN, Arc::clone(&handle), async {
        select_upstream(&route, None).await
    })
    .await;

    assert!(
        matches!(upstream, Some(Upstream::Tcp(_))),
        "with no other tier configured the ladder lands on TCP"
    );
    handle.shutdown().await;

    let day = std::fs::read_dir(&dir)
        .expect("the segment directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find_map(|name| name.strip_suffix(".seg").map(str::to_string))
        .expect("one segment for today");

    let records: Vec<_> = crate::log::storage::iter_batches(&dir, &day)
        .expect("the segment it just wrote is readable")
        .into_iter()
        .flat_map(|batch| batch.records)
        .collect();

    let attempt = records
        .iter()
        .find_map(|record| match &record.event {
            Some(crate::log::schema::Event::TierAttempt(attempt)) => Some((record, attempt)),
            _ => None,
        })
        .expect("the failed dial emitted a tier_attempt");

    assert_eq!(
        attempt.0.conn_id, CONN,
        "attributed to the dialling session"
    );
    assert_eq!(
        attempt.0.category,
        crate::log::schema::Category::Routing as i32
    );
    // A dial that failed is a warning and one that carried the connection is
    // info, which is the level alignment the event catalog asks for: an `info`
    // floor keeps every session's outcome and `debug` adds the successful
    // dials on top.
    assert_eq!(attempt.0.level, crate::log::schema::Level::Warn as i32);
    let ctx = attempt
        .1
        .ctx
        .as_ref()
        .expect("the attempt carries its session");
    assert_eq!(ctx.tier, LogTier::Ws as i32);
    assert_eq!(ctx.dc, 2);
    assert!(!attempt.1.ok);
    assert_eq!(attempt.1.err, ErrorCode::TcpConnect as i32);
    assert_eq!(attempt.1.err_code, 0);
    assert!(
        attempt.1.host.starts_with("kws2"),
        "the record names the host the walk ended on: {:?}",
        attempt.1.host
    );
    assert_ne!(
        attempt.1.errno, 0,
        "a refused connect is an OS error, and the record keeps the number"
    );

    let attempts = records
        .iter()
        .filter(|record| {
            matches!(
                record.event,
                Some(crate::log::schema::Event::TierAttempt(_))
            )
        })
        .count();
    assert_eq!(
        attempts, 1,
        "only the rung that dialled is an attempt; TCP connects inside its bridge"
    );

    let fallback = records
        .iter()
        .find_map(|record| match &record.event {
            Some(crate::log::schema::Event::TierFallback(fallback)) => Some((record, fallback)),
            _ => None,
        })
        .expect("the skipped WebSocket rung recorded the step down");

    assert_eq!(fallback.0.conn_id, CONN);
    assert_eq!(
        fallback.0.category,
        crate::log::schema::Category::Routing as i32
    );
    assert_eq!(fallback.0.level, crate::log::schema::Level::Info as i32);
    assert_eq!(fallback.1.from_tier, LogTier::Ws as i32);
    assert_eq!(
        fallback.1.to_tier,
        LogTier::Tcp as i32,
        "nothing else is configured, so TCP is where the ladder falls"
    );
    assert_eq!(
        fallback.1.reason,
        crate::log::schema::Reason::NotInDcIp as i32
    );

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}

/// The aligned level policy, read back out of a segment.
///
/// The levels are the event catalog's, not the caller's taste: a dial that
/// failed is a warning and one that carried the connection is info, a rung the
/// ladder passed over is a debug note, and the cooldown an outage arms is a
/// warning while the success that clears it is a debug note. `info` is the
/// disk floor, so this is also the difference between "the ladder is visible in
/// a segment" and "only the failures are".
#[cfg(feature = "log-disk")]
#[tokio::test]
async fn the_aligned_levels_land_in_the_segment() {
    use crate::log::schema::{AttemptSkipped, CooldownArmed, CooldownCleared, Event, TlsHandshake};

    let dir = std::env::temp_dir().join(format!("tgws-levels-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--pool-size",
        "0",
        "--log-dir",
        dir.to_str().expect("a utf-8 temp path"),
        "--log-level",
        "debug",
        "--log-durability",
        "immediate",
    ])
    .unwrap()
    .with_defaults();

    let handle = crate::log::init(config.log_settings(), config.log_disk())
        .expect("a writable temp dir accepts a segment");
    let ctx = || Some(Ctx::new(2, false, LogTier::Ws));

    crate::log::scope(1, Arc::clone(&handle), async {
        let connect_failure = RungFailure {
            err: ErrorCode::TcpConnect,
            err_code: 0,
            errno: 111,
        };
        let tls = TlsCost {
            kind: crate::log::schema::HandshakeKind::Full as i32,
            dur_ns: 1_200_000,
            err: 0,
            errno: 0,
        };

        log_tier_attempt(
            ctx(),
            "kws2.web.telegram.org",
            false,
            Duration::from_millis(305),
            Some(connect_failure),
            Some(tls),
        );
        log_tier_attempt(
            ctx(),
            "kws2.web.telegram.org",
            true,
            Duration::from_millis(312),
            None,
            None,
        );
        log_attempt_skipped(ctx(), UpstreamTier::Ws, LogReason::IpCooldown);
        log_cooldown_armed(
            ctx(),
            CooldownKind::WsFail,
            "DC2",
            Duration::from_secs(30),
            Some(connect_failure),
        );
        log_cooldown_cleared(ctx(), CooldownKind::WsFail, "DC2");
    })
    .await;
    handle.shutdown().await;

    let day = std::fs::read_dir(&dir)
        .expect("the segment directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find_map(|name| name.strip_suffix(".seg").map(str::to_string))
        .expect("one segment for today");

    let records: Vec<_> = crate::log::storage::iter_batches(&dir, &day)
        .expect("the segment it just wrote is readable")
        .into_iter()
        .flat_map(|batch| batch.records)
        .collect();

    let levels: Vec<(i32, &'static str)> = records
        .iter()
        .map(|record| {
            let name = match &record.event {
                Some(Event::TierAttempt(_)) => "tier_attempt",
                Some(Event::TlsHandshake(_)) => "tls_handshake",
                Some(Event::AttemptSkipped(_)) => "attempt_skipped",
                Some(Event::CooldownArmed(_)) => "cooldown_armed",
                Some(Event::CooldownCleared(_)) => "cooldown_cleared",
                _ => "other",
            };

            (record.level, name)
        })
        .collect();

    assert_eq!(
        levels,
        [
            (Level::Warn as i32, "tier_attempt"),
            (Level::Debug as i32, "tls_handshake"),
            (Level::Info as i32, "tier_attempt"),
            (Level::Debug as i32, "attempt_skipped"),
            (Level::Warn as i32, "cooldown_armed"),
            (Level::Debug as i32, "cooldown_cleared"),
        ],
        "the catalog's levels, in the order they were emitted"
    );

    // The fields the alignment was for: a failed attempt carries the host it
    // ended on, the class, the OS error behind it — and the handshake that got
    // that far.
    let attempt = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::TierAttempt(attempt)) if !attempt.ok => Some(attempt),
            _ => None,
        })
        .expect("the failed dial");
    assert_eq!(attempt.host, "kws2.web.telegram.org");
    assert_eq!(attempt.errno, 111);
    assert_eq!(attempt.dur_ns, 305_000_000);

    let handshake = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::TlsHandshake(TlsHandshake { kind, dur_ns, .. })) => Some((*kind, *dur_ns)),
            _ => None,
        })
        .expect("the handshake behind the dial");
    assert_eq!(
        handshake,
        (crate::log::schema::HandshakeKind::Full as i32, 1_200_000)
    );

    let skipped = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::AttemptSkipped(AttemptSkipped { tier, reason, .. })) => {
                Some((*tier, *reason))
            }
            _ => None,
        })
        .expect("the rung that was passed over");
    assert_eq!(skipped, (LogTier::Ws as i32, LogReason::IpCooldown as i32));

    let armed = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::CooldownArmed(CooldownArmed { err, dur_s, .. })) => Some((*err, *dur_s)),
            _ => None,
        })
        .expect("the cooldown the failure armed");
    assert_eq!(
        armed,
        (ErrorCode::TcpConnect as i32, 30),
        "the penalty and the offence that earned it"
    );

    let cleared = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::CooldownCleared(CooldownCleared { key_display, .. })) => {
                Some(key_display.clone())
            }
            _ => None,
        })
        .expect("the cleared entry");
    assert_eq!(cleared, "DC2");

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}

/// A session the ladder cannot route closes with `no_route` instead of simply
/// stopping.
///
/// DC 6 has no built-in address and the fixture passes no `--dc-ip`, so there
/// is no rung to dial. An opened session with no close record is what a crashed
/// process looks like in a segment; this is the record that tells the two
/// apart.
#[cfg(feature = "log-disk")]
#[tokio::test]
async fn a_session_with_nowhere_to_route_closes_as_no_route() {
    use crate::log::schema::{ClosedBy, Event};

    let dir = std::env::temp_dir().join(format!("tgws-no-route-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--pool-size",
        "0",
        "--log-dir",
        dir.to_str().expect("a utf-8 temp path"),
        "--log-level",
        "info",
        "--log-durability",
        "immediate",
    ])
    .unwrap()
    .with_defaults();

    let handle = crate::log::init(config.log_settings(), config.log_disk())
        .expect("a writable temp dir accepts a segment");

    let config = Arc::new(config);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(60),
        Arc::clone(&runtime),
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(client, accept);
    let (mut client, (server, peer)) = (client.unwrap(), accepted.unwrap());

    const CONN: u64 = 1;
    let client_task = handle_client_with_runtime(
        server,
        peer,
        Arc::clone(&config),
        pool,
        Arc::clone(&runtime),
    );
    let handler = tokio::spawn(crate::log::scope(CONN, Arc::clone(&handle), client_task));

    let (handshake, _, _) = crate::crypto::generate_client_handshake(
        &config.secret_bytes(),
        6,
        ProtoTag::PaddedIntermediate,
    );
    client.write_all(&handshake).await.unwrap();
    drop(client);
    handler
        .await
        .expect("the handler runs the ladder to its end");
    handle.shutdown().await;

    let day = std::fs::read_dir(&dir)
        .expect("the segment directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find_map(|name| name.strip_suffix(".seg").map(str::to_string))
        .expect("one segment for today");

    let records: Vec<_> = crate::log::storage::iter_batches(&dir, &day)
        .expect("the segment it just wrote is readable")
        .into_iter()
        .flat_map(|batch| batch.records)
        .collect();

    let session: Vec<_> = records
        .iter()
        .filter(|record| record.conn_id == CONN)
        .filter_map(|record| record.event.as_ref())
        .collect();

    assert_eq!(
        session
            .iter()
            .filter(|event| matches!(event, Event::SessionOpened(_)))
            .count(),
        1,
        "the session opened: the client's handshake was valid"
    );

    let closed = session
        .iter()
        .find_map(|event| match event {
            Event::SessionClosed(closed) => Some(closed),
            _ => None,
        })
        .expect("a session with nowhere to go still closes");

    assert_eq!(closed.closed_by, ClosedBy::NoRoute as i32);
    assert_eq!(closed.bytes_up, 0);
    assert_eq!(closed.bytes_down, 0);
    assert!(
        closed.via.is_empty(),
        "no host carried the session, so there is none to name"
    );

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}

// ─── A pinned ladder and a cooled `--dc-ip` ──────────────────────────────────

// `WS_FAIL` and `IP_FAIL` are process-global maps shared by every test in this
// binary, so each ladder test uses its own DC number (non-canonical test DCs)
// and its own IP address to prevent concurrent runs in libtest from wiping each
// other's state.
const LADDER_DC_STEP_OVER: u32 = 201;
const LADDER_IP_STEP_OVER: &str = "192.0.2.10"; // RFC 5737

const LADDER_DC_NO_LATER_RUNG: u32 = 202;
const LADDER_IP_NO_LATER_RUNG: &str = "192.0.2.11";

const LADDER_DC_RE_PROBE: u32 = 203;
const LADDER_IP_RE_PROBE: &str = "192.0.2.12";

fn ladder_config(extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        // A dial to a blackholed address has to be bounded by the test, not by
        // the default ten seconds.
        "--ws-connect-timeout",
        "1",
        "--pool-size",
        "0",
        "--no-outbound-proxy",
    ];
    args.extend_from_slice(extra);
    Config::try_parse_from(args).unwrap()
}

fn ladder_route<'a>(
    config: &'a Config,
    runtime: &'a Arc<Runtime>,
    pool: &'a Arc<WsPool>,
    dc: u32,
) -> Route<'a> {
    Route {
        config,
        runtime,
        pool,
        timeouts: Timeouts::from_config(config),
        dc,
        is_media: false,
        media: media_tag(false),
        dc_idx: dc as i16,
        proto: ProtoTag::Intermediate,
    }
}

#[tokio::test]
async fn a_pinned_ladder_steps_over_a_cooled_dc_ip() {
    // A pin replaces the default ladder, and the cooldown skip lives in the
    // default ladder.  Without it here, `--pinned-upstream ws,…` re-dials an
    // address that has already timed out on every cold-pool client, and each of
    // those waits out `--ws-connect-timeout` once per `kws` record before the
    // pin's next rung gets a turn.
    let config = ladder_config(&[]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_STEP_OVER);
    let ws_fail_key = (LADDER_DC_STEP_OVER, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_STEP_OVER.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(
            &[UpstreamTier::Ws, UpstreamTier::Tcp],
            Some(LADDER_IP_STEP_OVER),
        )
        .await;

    // A dial is what arms `WS_FAIL`, so leaving it clear is proof that the
    // cooled address never reached the connector -- the same signal the log's
    // "skipping direct WS" line carries, without needing a network.
    let dialled_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_STEP_OVER);

    assert!(
        matches!(upstream, Some(Upstream::Tcp(_))),
        "the rung after the skipped one is the one that connects"
    );
    assert!(
        !dialled_the_cooled_ip,
        "the pinned ladder dialled the cooled {LADDER_IP_STEP_OVER} again"
    );
}

#[tokio::test]
async fn a_pin_with_no_later_rung_dials_its_cooled_dc_ip_anyway() {
    // Stepped over, not written off: the cooldown is worth honouring only while
    // a later rung can connect.  A `ws`-only pin has no later rung, so the
    // cooled address is the client's only way out, and the doomed attempt beats
    // dropping the connection.
    let config = ladder_config(&[]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_NO_LATER_RUNG);
    let ws_fail_key = (LADDER_DC_NO_LATER_RUNG, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_NO_LATER_RUNG.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(&[UpstreamTier::Ws], Some(LADDER_IP_NO_LATER_RUNG))
        .await;

    let dialled_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_NO_LATER_RUNG);

    assert!(upstream.is_none(), "a pin has nothing to fall back to");
    assert!(
        dialled_the_cooled_ip,
        "the only rung was skipped, which leaves the client nowhere to go"
    );
}

#[tokio::test]
async fn a_pinned_ladder_re_probes_a_cooled_dc_ip_when_every_rung_fails() {
    // The other half of the rule: a skip must not become a dead end for the
    // rest of the cooldown.  An `--mtproto-proxy` on a closed local port fails
    // without a network the way a dead upstream does, so the last thing the
    // ladder has left is the address it stepped over — and asking it is what
    // keeps the cooldown self-healing, since only a successful direct connect
    // clears it.
    let config = ladder_config(&[
        "--mtproto-proxy",
        "127.0.0.1:1:00112233445566778899aabbccddeeff",
    ]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_RE_PROBE);
    let ws_fail_key = (LADDER_DC_RE_PROBE, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_RE_PROBE.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(
            &[UpstreamTier::Ws, UpstreamTier::Mtproto],
            Some(LADDER_IP_RE_PROBE),
        )
        .await;

    let re_probed_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_RE_PROBE);

    assert!(upstream.is_none(), "nothing in the pin can connect");
    assert!(
        re_probed_the_cooled_ip,
        "the cooled address was never asked again, so nothing can clear it"
    );
}

// ─── The background probe of a cooled `--dc-ip` ──────────────────────────────

/// An outbound HTTP proxy that counts CONNECTs and either holds them open
/// without a word — a dark address, as far as the dialler can tell — or
/// refuses them, which is an address that answers.
async fn probe_outbound(answer: bool) -> (Arc<Runtime>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dials = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&dials);
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            if answer {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            } else {
                held.push(stream);
            }
        }
    });

    let outbound = OutboundConnector::from_config(Some(&format!("http://{addr}")), None, false);
    (Arc::new(Runtime::new(outbound.unwrap())), dials)
}

fn probe(runtime: &Arc<Runtime>, ip: &str, cooldown: Duration) -> IpProbe {
    IpProbe {
        runtime: Arc::clone(runtime),
        ip: ip.to_string(),
        dc: 2,
        is_media: false,
        skip_tls_verify: false,
        connect_timeout: Duration::from_millis(500),
        cooldown,
        // The probe records through the handle a scope hands it; a test starts
        // one outside any scope, so there is nothing to record into.
        log: None,
    }
}

async fn probe_finished(ip: &str) -> bool {
    for _ in 0..60 {
        if !IP_PROBES.lock().unwrap().contains(ip) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn a_cooled_dc_ip_stays_cooled_while_the_probe_finds_it_dark() {
    // #148: the cooldown used to simply run out, and the next client dialled
    // the address on the full connect timeout.  The entry now outlives the
    // window until the probe has its answer, and a probe that times out again
    // re-arms it.
    const IP: &str = "192.0.2.20";
    let (runtime, dials) = probe_outbound(false).await;
    let cooldown = Duration::from_millis(200);

    probe(&runtime, IP, cooldown).arm();
    // A second timeout while the first probe waits must not start another.
    probe(&runtime, IP, cooldown).arm();

    // Mid-probe: past the bare cooldown, before the 500 ms connect gives up.
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(
        IP_FAIL.active(IP),
        "a client could dial the address mid-probe"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1, "one probe per address");

    // The probe gave up at ~700 ms and re-armed the entry.
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(IP_FAIL.active(IP), "a dark address came back by itself");

    // A client's direct connect clearing the entry ends the probe.
    IP_FAIL.clear(IP);
    assert!(probe_finished(IP).await, "the probe outlived its entry");
}

#[tokio::test]
async fn a_cooled_dc_ip_that_answers_the_probe_comes_back() {
    // Any answer clears it, exactly as in `direct_ws`: only a connect that ran
    // out the clock says the address itself is gone.
    const IP: &str = "192.0.2.21";
    let (runtime, dials) = probe_outbound(true).await;

    probe(&runtime, IP, Duration::from_millis(50)).arm();

    assert!(probe_finished(IP).await, "the probe never finished");
    assert!(dials.load(Ordering::SeqCst) >= 1);
    assert!(
        !IP_FAIL.active(IP),
        "an address that answered stayed cooled"
    );
}

#[tokio::test]
async fn a_zero_ip_fail_cooldown_starts_no_probe() {
    // `--ip-fail-cooldown 0` turns the skipping off.  Holding the entry for a
    // probe's grace period would quietly turn it back on.
    const IP: &str = "192.0.2.22";
    let (runtime, dials) = probe_outbound(false).await;

    probe(&runtime, IP, Duration::ZERO).arm();

    assert!(!IP_FAIL.active(IP));
    assert!(!IP_PROBES.lock().unwrap().contains(IP));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

// ─── Pool spares under `--cf-balance` ────────────────────────────────────────

#[test]
fn a_balanced_cf_proxy_spare_is_dialled_at_the_kws_record() {
    // #161: with `--cf-balance` the spare's domain comes from the rotation,
    // which holds bare zones.  The pool dials it as-is, so every balanced
    // spare went to the zone apex — no record there, a 530 from Cloudflare,
    // and half of the `/apiws` requests in the reporter's analytics failing.
    let config = ladder_config(&[
        "--cf-domain",
        "a.example",
        "--cf-domain",
        "b.example",
        "--cf-balance",
    ]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, 203);
    let counter = AtomicUsize::new(0);

    let picks: Vec<_> = (0..2)
        .map(|_| {
            route
                .cf_target(
                    CfTier::Proxy,
                    "",
                    "kws203.a.example",
                    &config.cf_domains,
                    &counter,
                )
                .domain
        })
        .collect();
    assert_eq!(picks, ["kws203.a.example", "kws203.b.example"]);

    // A Worker is dialled at its own name; there is no record to expand.
    let workers = vec!["w.example".to_string()];
    let worker = route.cf_target(
        CfTier::Worker,
        "149.154.167.51",
        "w.example",
        &workers,
        &counter,
    );
    assert_eq!(worker.domain, "w.example");
}

#[test]
fn an_unbalanced_cf_proxy_spare_keeps_the_record_that_answered() {
    let config = ladder_config(&["--cf-domain", "a.example", "--cf-domain", "b.example"]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, 2);

    let target = route.cf_target(
        CfTier::Proxy,
        "",
        "kws2.b.example",
        &config.cf_domains,
        &AtomicUsize::new(0),
    );
    assert_eq!(target.domain, "kws2.b.example");
}

// ─── The re-probe as a record ────────────────────────────────────────────────

/// The re-probe is not only a dial: a pinned ladder that stepped over a cooled
/// address has to say it came back for it. Without the record a segment shows
/// the skip and then a session that never routed, which is exactly the shape a
/// dead end has — and the one thing that could still save the client is lost.
#[cfg(feature = "log-disk")]
#[tokio::test]
async fn a_pinned_re_probe_lands_in_the_segment() {
    let dir = std::env::temp_dir().join(format!("tgws-reprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = ladder_config(&[
        "--mtproto-proxy",
        "127.0.0.1:1:00112233445566778899aabbccddeeff",
        "--log-dir",
        dir.to_str().expect("a utf-8 temp path"),
        "--log-level",
        "debug",
        "--log-batch-max",
        "16",
        "--log-durability",
        "immediate",
    ])
    .with_defaults();

    let handle = crate::log::init(config.log_settings(), config.log_disk())
        .expect("a writable temp dir accepts a segment");
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_RE_PROBE);

    WS_FAIL.clear(&(LADDER_DC_RE_PROBE, false));
    IP_FAIL.set(LADDER_IP_RE_PROBE.to_string(), Duration::from_secs(60));

    const CONN: u64 = 7;
    let upstream = crate::log::scope(CONN, Arc::clone(&handle), async {
        route
            .pinned_ladder(
                &[UpstreamTier::Ws, UpstreamTier::Mtproto],
                Some(LADDER_IP_RE_PROBE),
            )
            .await
    })
    .await;

    WS_FAIL.clear(&(LADDER_DC_RE_PROBE, false));
    IP_FAIL.clear(LADDER_IP_RE_PROBE);
    assert!(upstream.is_none(), "nothing in the pin can connect");
    handle.shutdown().await;

    let day = std::fs::read_dir(&dir)
        .expect("the segment directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find_map(|name| name.strip_suffix(".seg").map(str::to_string))
        .expect("one segment for today");

    let records: Vec<_> = crate::log::storage::iter_batches(&dir, &day)
        .expect("the segment it just wrote is readable")
        .into_iter()
        .flat_map(|batch| batch.records)
        .collect();

    let (record, reprobe) = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::CooldownReprobe(reprobe)) => Some((record, reprobe)),
            _ => None,
        })
        .expect("the re-probe emitted its record");

    assert_eq!(record.conn_id, CONN, "attributed to the pinned session");
    assert_eq!(record.category, Category::Cooldown as i32);
    assert_eq!(record.level, Level::Info as i32);
    assert_eq!(reprobe.kind, CooldownKind::IpFail as i32);
    assert_eq!(reprobe.key_display, LADDER_IP_RE_PROBE);
    assert_eq!(
        reprobe.ctx.as_ref().map(|ctx| ctx.tier),
        Some(LogTier::Ws as i32)
    );
    assert_eq!(
        reprobe.ctx.as_ref().map(|ctx| ctx.dc),
        Some(LADDER_DC_RE_PROBE)
    );

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}
