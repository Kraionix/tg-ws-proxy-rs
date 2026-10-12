use super::*;

use clap::Parser;

use crate::log::schema::ErrorCode;
use tokio_tungstenite::MaybeTlsStream;

#[test]
fn direct_refill_is_reserved_before_a_task_can_be_spawned() {
    let pool = WsPool::new(4, Duration::from_secs(60));
    let key = (2, true);

    assert!(pool.reserve_refill(key));
    for _ in 0..1_000 {
        assert!(!pool.reserve_refill(key));
    }
    assert_eq!(pool.refilling.lock().unwrap().len(), 1);
}

#[test]
fn cloudflare_refill_is_reserved_before_a_task_can_be_spawned() {
    let pool = WsPool::new(4, Duration::from_secs(60));
    let key = (CfTier::Worker, 2, true);

    assert!(pool.reserve_cf_refill(key));
    for _ in 0..1_000 {
        assert!(!pool.reserve_cf_refill(key));
    }
    assert_eq!(pool.cf_refilling.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_direct_miss_burst_spawns_one_refill_task() {
    let pool = Arc::new(WsPool::new(4, Duration::from_secs(60)));

    for _ in 0..1_000 {
        pool.schedule_refill(2, true, "203.0.113.10", false);
    }

    assert_eq!(pool.refill_task_spawns.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_cloudflare_prefetch_burst_spawns_one_refill_task() {
    let pool = Arc::new(WsPool::new(4, Duration::from_secs(60)));

    for _ in 0..1_000 {
        pool.cf_prefetch(CfTarget {
            tier: CfTier::Worker,
            dc: 2,
            is_media: true,
            dst: "149.154.167.51".to_string(),
            domain: "worker.example".to_string(),
            skip_tls_verify: false,
            connect_timeout: Duration::from_secs(1),
            disable_tls: false,
        });
    }

    assert_eq!(pool.cf_refill_task_spawns.load(Ordering::Relaxed), 1);
}

/// The pool reports a miss even when the call came from inside a connection,
/// and reports it as the pool's own — `conn_id = 0`, not the session's (S7).
///
/// The attribute is the whole point: a refill is spawned from whichever
/// connection happened to arrive first, and a record that inherited that
/// connection's id would read as if the session had done the dialling.
#[tokio::test]
async fn a_miss_is_recorded_against_the_pool_rather_than_the_caller() {
    let dir = std::env::temp_dir().join(format!("tgws-pool-events-{}", std::process::id()));
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
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(
        WsPool::with_runtime(0, Duration::from_secs(60), runtime)
            .with_log(Some(Arc::clone(&handle))),
    );

    // `allow_refill` is false so the miss is the only thing this can emit: a
    // refill would dial out and write records of its own.
    let hit = crate::log::scope(42, Arc::clone(&handle), async {
        pool.get(2, false, "203.0.113.10", false, false).await
    })
    .await;

    assert!(hit.is_none(), "an empty pool has nothing to hand out");
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

    let miss = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::PoolMiss(miss)) => Some((record, miss)),
            _ => None,
        })
        .expect("the empty bucket emitted a pool_miss");

    assert_eq!(miss.0.conn_id, 0, "a pool record belongs to the pool");
    assert_eq!(miss.0.category, Category::Pool as i32);
    assert_eq!(miss.0.level, Level::Debug as i32);
    let ctx = miss.1.ctx.as_ref().expect("the miss carries its bucket");
    assert_eq!(ctx.dc, 2);
    assert!(!ctx.is_media);
    assert_eq!(ctx.tier, Tier::Ws as i32);

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}

/// A local WebSocket pair, for the pool entries these tests need a real
/// connection for: the pool holds `TgWsStream`s, and a `PoolDiscard` is about
/// what happens to one of them.
async fn ws_pair() -> (TgWsStream, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = tokio_tungstenite::accept_async(stream).await;

        // Held open until the test drops the client end.
        std::future::pending::<()>().await;
    });

    let (ws, _) = tokio_tungstenite::client_async(
        format!("ws://{addr}/"),
        MaybeTlsStream::Plain(tokio::net::TcpStream::connect(addr).await.unwrap()),
    )
    .await
    .unwrap();

    (ws, server)
}

/// The pool's own records, read back out of a segment: an idle connection
/// thrown away says which one and why, a warm-up says how much the pool is
/// worth, and a refill that dialled into nothing carries the class it failed
/// with.
#[tokio::test]
async fn discards_warmup_and_refills_are_recorded() {
    use crate::log::schema::{DiscardReason, WarmupComplete};

    let dir = std::env::temp_dir().join(format!("tgws-pool-shed-{}", std::process::id()));
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
    let pool = Arc::new(
        WsPool::with_runtime(
            4,
            Duration::from_secs(30),
            Arc::new(Runtime::new(OutboundConnector::direct())),
        )
        .with_log(Some(Arc::clone(&handle))),
    );

    // One entry older than the pool's age limit, and one the server has already
    // closed: the two reasons an idle connection is thrown away.
    let (stale, stale_server) = ws_pair().await;
    let (mut closed, closed_server) = ws_pair().await;
    closed.close(None).await.unwrap();

    {
        let mut idle = pool.idle.lock().await;
        let bucket = idle.entry((2, false)).or_default();
        bucket.push(PoolEntry {
            ws: stale,
            created: Instant::now() - Duration::from_secs(120),
        });
        bucket.push(PoolEntry {
            ws: closed,
            created: Instant::now(),
        });
    }

    // `allow_refill` is false: a refill would dial out on this empty pool.
    let hit = pool.get(2, false, "127.0.0.1", false, false).await;
    assert!(hit.is_none(), "both entries were unusable");

    pool.log_warmup(3, Duration::from_millis(241));
    pool.log_refill(
        Tier::Ws,
        2,
        false,
        Refill {
            added: 0,
            ready: 0,
            dur: Duration::from_secs(8),
            failure: Some(RungFailure {
                err: ErrorCode::TcpConnectTimeout,
                err_code: 0,
                errno: 113,
            }),
        },
    );

    stale_server.abort();
    closed_server.abort();
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

    let discards: Vec<i32> = records
        .iter()
        .filter_map(|record| match &record.event {
            Some(Event::PoolDiscard(discard)) => Some(discard.reason),
            _ => None,
        })
        .collect();
    assert_eq!(
        discards,
        [DiscardReason::Closed as i32, DiscardReason::Stale as i32],
        "one record per connection thrown away, freshest first: the pool \
         drains its bucket LIFO"
    );

    let warmup = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::WarmupComplete(WarmupComplete { ready, dur_ms })) => {
                Some((*ready, *dur_ms))
            }
            _ => None,
        })
        .expect("the warm-up is one process-wide record");
    assert_eq!(warmup, (3, 241));

    let refill = records
        .iter()
        .find_map(|record| match &record.event {
            Some(Event::PoolRefill(refill)) if refill.err != 0 => Some(refill),
            _ => None,
        })
        .expect("the refill that produced nothing still says why");
    assert_eq!(refill.err, ErrorCode::TcpConnectTimeout as i32);
    assert_eq!(refill.errno, 113);
    assert_eq!(refill.added, 0);

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}
