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

    let handle = crate::log::init(&dir, config.log_settings(), config.log_options())
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
        .find_map(|name| name.strip_suffix(".redb").map(str::to_string))
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

    let handle = crate::log::init(&dir, config.log_settings(), config.log_options())
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
        .find_map(|name| name.strip_suffix(".redb").map(str::to_string))
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

    let handle = crate::log::init(&dir, config.log_settings(), config.log_options())
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
        .find_map(|name| name.strip_suffix(".redb").map(str::to_string))
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
