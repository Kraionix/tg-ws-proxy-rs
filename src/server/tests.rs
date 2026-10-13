//! The one test here reads a segment back, so the file needs the sink that
//! writes one: without the `log-disk` feature there is nothing to assert on.
#![cfg(feature = "log-disk")]

use super::*;

use clap::Parser;

use crate::default_domains::FetchError;

/// The domain list's provenance is a warning when the built-in list is what
/// runs, and it says which failure put it there.
///
/// The distinction is the record's whole reason to exist: `--default-domains`
/// asked for the community list, and "GitHub was unreachable" is a different
/// thing to fix from "the list came back empty".
#[tokio::test]
async fn the_domain_list_records_where_it_came_from() {
    let dir = std::env::temp_dir().join(format!("tgws-domains-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = crate::config::Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--log-dir",
        dir.to_str().expect("a utf-8 temp path"),
        "--log-level",
        "debug",
        "--log-durability",
        "immediate",
    ])
    .expect("the fixture parses");

    let handle = log::init(config.log_settings(), config.log_disk())
        .expect("a writable temp dir accepts a segment");

    log_domain_list(
        &handle,
        &Fetched {
            domains: vec!["a.co.uk".to_string(), "b.co.uk".to_string()],
            source: DomainSource::Github,
            failure: None,
        },
    );
    log_domain_list(
        &handle,
        &Fetched {
            domains: vec!["c.co.uk".to_string()],
            source: DomainSource::Builtin,
            failure: Some(FetchError {
                err: ErrorCode::TcpConnectTimeout,
                err_code: 0,
                reason: "TCP connect timed out".to_string(),
            }),
        },
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

    let fetched: Vec<_> = records
        .iter()
        .filter_map(|record| match &record.event {
            Some(Event::DomainListFetched(fetched)) => {
                Some((record.level, fetched.source, fetched.count, fetched.err))
            }
            _ => None,
        })
        .collect();

    assert_eq!(
        fetched,
        [
            (
                Level::Info as i32,
                DomainSource::Github as i32,
                2,
                ErrorCode::Unspecified as i32,
            ),
            (
                Level::Warn as i32,
                DomainSource::Builtin as i32,
                1,
                ErrorCode::TcpConnectTimeout as i32,
            ),
        ],
        "the fetch that worked is info, the fallback is a warning that says why"
    );

    std::fs::remove_dir_all(&dir).expect("the temp dir is ours");
}
