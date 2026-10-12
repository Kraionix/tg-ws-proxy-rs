use super::*;

use clap::Parser;

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
