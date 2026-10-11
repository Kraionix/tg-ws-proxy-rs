use prost::Message;

use super::schema::*;

/// A record with a fixed, non-zero envelope: every sample differs only in its
/// payload, which is the part whose size the storage budget depends on.
fn record(event: Event) -> LogRecord {
    LogRecord {
        ts_ns: 1_700_000_000_123_456_789,
        conn_id: 42,
        seq: 7,
        level: Level::Info as i32,
        category: Category::Routing as i32,
        event: Some(event),
    }
}

/// One representative record per `oneof` variant, named after its `EVT:*`.
fn samples() -> Vec<(&'static str, LogRecord)> {
    vec![
        (
            "session_opened",
            record(Event::SessionOpened(SessionOpened {
                dc: 2,
                is_media: false,
                peer: Some(Peer {
                    addr: vec![203, 0, 113, 5],
                    port: 51234,
                    hashed: false,
                    encrypted: false,
                }),
            })),
        ),
        (
            "session_closed",
            record(Event::SessionClosed(SessionClosed {
                dc: 2,
                is_media: true,
                tier: Tier::Ws as i32,
                closed_by: ClosedBy::Upstream as i32,
                bytes_up: 1 << 20,
                bytes_down: 1 << 22,
                dur_ms: 120_000,
            })),
        ),
        (
            "tier_attempt",
            record(Event::TierAttempt(TierAttempt {
                tier: Tier::Cfproxy as i32,
                dc: 4,
                is_media: true,
                ok: false,
                dur_ns: 2_500_000_000,
                err: ErrorCode::TlsTimeout as i32,
                err_code: 0,
            })),
        ),
        (
            "tier_fallback",
            record(Event::TierFallback(TierFallback {
                from_tier: Tier::Ws as i32,
                to_tier: Tier::Cfworker as i32,
                reason: Reason::WsFail as i32,
            })),
        ),
        (
            "cooldown_armed",
            record(Event::CooldownArmed(CooldownArmed {
                kind: CooldownKind::WsFail as i32,
                key_display: "kws2.web.telegram.org:443".to_string(),
                dur_s: 300,
                err: ErrorCode::HttpStatus as i32,
                err_code: 403,
            })),
        ),
        (
            "cooldown_cleared",
            record(Event::CooldownCleared(CooldownCleared {
                kind: CooldownKind::IpFail as i32,
                key_display: "149.154.167.220".to_string(),
            })),
        ),
        (
            "cooldown_skipped",
            record(Event::CooldownSkipped(CooldownSkipped {
                kind: CooldownKind::UpstreamFail as i32,
                key_display: "proxy.example:443".to_string(),
            })),
        ),
        (
            "pool_hit",
            record(Event::PoolHit(PoolHit {
                dc: 2,
                is_media: false,
            })),
        ),
        (
            "pool_miss",
            record(Event::PoolMiss(PoolMiss {
                dc: 2,
                is_media: true,
            })),
        ),
        (
            "pool_refill",
            record(Event::PoolRefill(PoolRefill {
                dc: 203,
                is_media: false,
                added: 4,
                dur_ms: 850,
            })),
        ),
        (
            "tls_handshake",
            record(Event::TlsHandshake(TlsHandshake {
                kind: HandshakeKind::Full as i32,
                dur_ns: 180_000_000,
            })),
        ),
        (
            "relay_init_retries",
            record(Event::RelayInitRetries(RelayInitRetries { n: 3 })),
        ),
        (
            "accept_error",
            record(Event::AcceptError(AcceptError {
                errno: 24,
                backoff_ms: 100,
                err: ErrorCode::Resource as i32,
            })),
        ),
        (
            "fd_snapshot",
            record(Event::FdSnapshot(FdSnapshot {
                open: 214,
                soft_limit: 1024,
                sem_avail: 810,
            })),
        ),
        (
            "probe_result",
            record(Event::ProbeResult(ProbeResult {
                kind: ProbeKind::CfDomain as i32,
                target: "cf.example.com".to_string(),
                ok: false,
                dur_ns: 90_000_000,
                err: ErrorCode::HttpStatus as i32,
                err_code: 502,
            })),
        ),
        (
            "log_overflow",
            record(Event::LogOverflow(LogOverflow {
                dropped: 12,
                window_ns: 2_000_000_000,
            })),
        ),
        (
            "startup_summary",
            record(Event::StartupSummary(StartupSummary {
                version: "2.6.0".to_string(),
                listen: "127.0.0.1:17443".to_string(),
                dc_ips: (1..=5)
                    .map(|dc| DcIp {
                        dc,
                        ip: format!("149.154.167.{dc}"),
                    })
                    .collect(),
                tiers: ["ws", "cfproxy", "cfworker", "mtproto", "tcp"]
                    .iter()
                    .map(|t| t.to_string())
                    .collect(),
                categories: ["session", "routing", "pool", "cooldown", "tls", "accept"]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            })),
        ),
    ]
}

fn sample(name: &str) -> LogRecord {
    samples()
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no sample named {name}"))
        .1
}

#[test]
fn every_event_variant_round_trips() {
    let samples = samples();
    assert_eq!(samples.len(), 17, "one sample per oneof variant");

    for (name, record) in samples {
        let encoded = record.encode_to_vec();
        let decoded = LogRecord::decode(encoded.as_slice())
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
        assert_eq!(decoded, record, "{name} did not survive the round trip");
        assert!(decoded.event.is_some(), "{name} lost its event");
    }
}

#[test]
fn every_field_survives_the_round_trip_individually() {
    // The whole-record comparison above is only as good as the fixture behind
    // it: a sample that quietly lost a field would make its test vacuous. These
    // are the values the size, mask and split assertions depend on.
    match sample("session_opened").event.unwrap() {
        Event::SessionOpened(e) => {
            let peer = e.peer.expect("the peer is part of the fixture");
            assert_eq!(peer.addr, vec![203, 0, 113, 5]);
            assert_eq!(peer.port, 51234);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("session_closed").event.unwrap() {
        Event::SessionClosed(e) => {
            assert_eq!((e.bytes_up, e.bytes_down), (1 << 20, 1 << 22));
            assert_eq!(e.closed_by, ClosedBy::Upstream as i32);
            assert_eq!(e.dur_ms, 120_000);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("tier_attempt").event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(e.err, ErrorCode::TlsTimeout as i32);
            assert_eq!(e.err_code, 0);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("cooldown_armed").event.unwrap() {
        Event::CooldownArmed(e) => {
            assert_eq!(e.key_display, "kws2.web.telegram.org:443");
            assert_eq!(e.err_code, 403);
        }
        other => panic!("wrong variant: {other:?}"),
    }
    match sample("startup_summary").event.unwrap() {
        Event::StartupSummary(e) => {
            assert_eq!(e.dc_ips.len(), 5);
            assert_eq!(e.dc_ips[4].ip, "149.154.167.5");
            assert_eq!(e.tiers.len(), 5);
            assert_eq!(e.categories.len(), 6);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn dc_bit_maps_the_documented_table() {
    assert_eq!(dc_bit(1), Some(0));
    assert_eq!(dc_bit(2), Some(1));
    assert_eq!(dc_bit(3), Some(2));
    assert_eq!(dc_bit(4), Some(3));
    assert_eq!(dc_bit(5), Some(4));
    assert_eq!(dc_bit(203), Some(5));

    // No collision between the six bits, and no bit outside the documented six.
    let mut seen = 0u32;
    for dc in [1, 2, 3, 4, 5, 203] {
        let bit = 1u32 << dc_bit(dc).unwrap();
        assert_eq!(seen & bit, 0, "dc {dc} shares a bit");
        seen |= bit;
    }
    assert_eq!(seen, 0b11_1111);

    // The artifact's formula underflows on these; they must be rejected, not
    // shifted into an unrelated slot.
    for absent in [0, 6, 202, 204, u32::MAX] {
        assert_eq!(dc_bit(absent), None, "dc {absent}");
    }
}

#[test]
fn header_masks_follow_the_records() {
    let mut records = vec![
        record(Event::SessionOpened(SessionOpened {
            dc: 2,
            is_media: true,
            peer: None,
        })),
        record(Event::SessionClosed(SessionClosed {
            dc: 203,
            is_media: false,
            tier: Tier::Ws as i32,
            closed_by: ClosedBy::Client as i32,
            bytes_up: 0,
            bytes_down: 0,
            dur_ms: 1,
        })),
        record(Event::TlsHandshake(TlsHandshake {
            kind: HandshakeKind::Full as i32,
            dur_ns: 1,
        })),
        record(Event::TierAttempt(TierAttempt {
            tier: Tier::Ws as i32,
            dc: 2,
            is_media: false,
            ok: true,
            dur_ns: 1,
            err: ErrorCode::Unspecified as i32,
            err_code: 0,
        })),
        // A record whose event never got set: counted, but contributing no bit.
        LogRecord {
            event: None,
            ..record(Event::PoolHit(PoolHit {
                dc: 1,
                is_media: false,
            }))
        },
        record(Event::PoolHit(PoolHit {
            dc: 1,
            is_media: false,
        })),
    ];

    for (i, ts_ns) in [300, 100, 500, 400, 200, 600].into_iter().enumerate() {
        records[i].ts_ns = ts_ns;
    }

    let batches = build_batch(&records);
    assert_eq!(batches.len(), 1);
    let header = batches[0].header.clone().unwrap();

    assert_eq!(header.record_count, 6);
    assert_eq!(header.ts_first_ns, 100);
    assert_eq!(header.ts_last_ns, 600);
    // session_opened 16, session_closed 17, tier_attempt 18, pool_hit 23,
    // tls_handshake 26 — with the eventless record's bit 4 staying clear.
    assert_eq!(
        header.kind_mask,
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 7) | (1 << 10)
    );
    // dc 1 → bit 0, dc 2 → bit 1, dc 203 → bit 5.
    assert_eq!(header.dc_mask, 0b10_0011);
    // Only the dc 2 session is a media session.
    assert_eq!(header.dc_media_mask, 0b10);
    assert_eq!(header.conn_ids, vec![42]);
    assert_eq!(batches[0].records, records);
}

#[test]
fn split_respects_the_unique_conn_bound() {
    // Two rounds over the same 16 connections do not split: the bound is on
    // distinct connections, not on record count.
    let mut records: Vec<LogRecord> = (0..2)
        .flat_map(|_| {
            (0..16u64).map(|conn| {
                event_for(
                    conn,
                    Event::PoolMiss(PoolMiss {
                        dc: 2,
                        is_media: false,
                    }),
                )
            })
        })
        .collect();
    assert_eq!(build_batch(&records).len(), 1);

    // A seventeenth connection in the middle splits where it appears, not at
    // the end and not on the record that happens to be last.
    records.insert(
        5,
        event_for(
            99,
            Event::PoolHit(PoolHit {
                dc: 2,
                is_media: false,
            }),
        ),
    );

    let batches = build_batch(&records);
    assert_eq!(batches.len(), 2);
    for batch in &batches {
        let header = batch.header.as_ref().unwrap();
        assert!(
            header.conn_ids.len() <= BATCH_MAX_UNIQUE_CONNS,
            "{header:?}"
        );
        assert_eq!(header.record_count as usize, batch.records.len());
        assert!(
            header.conn_ids.windows(2).all(|w| w[0] < w[1]),
            "conn_ids must be sorted and deduplicated: {header:?}"
        );
    }
    assert_eq!(
        batches[0].header.as_ref().unwrap().record_count,
        16,
        "the split happens on the record that would introduce a seventeenth connection"
    );

    let flattened: Vec<u64> = batches
        .iter()
        .flat_map(|b| b.records.iter().map(|r| r.conn_id))
        .collect();
    assert_eq!(
        flattened,
        records.iter().map(|r| r.conn_id).collect::<Vec<_>>()
    );
}

#[test]
fn empty_input_makes_no_batches() {
    assert!(build_batch(&[]).is_empty());
}

#[test]
fn truncated_records_error_instead_of_panicking() {
    let encoded = sample("session_closed").encode_to_vec();

    // A prefix that ends inside the fixed64 timestamp cannot be a record.
    assert!(LogRecord::decode(&encoded[..3]).is_err());
    // Field 2 is a varint; one whose continuation bit is set at the end of the
    // buffer is not a value.
    assert!(LogRecord::decode([0x10u8, 0x80].as_slice()).is_err());

    // Whatever the cut, decoding is total: no index-out-of-bounds, no panic.
    for cut in 0..encoded.len() {
        let _ = LogRecord::decode(&encoded[..cut]);
    }
}

#[test]
fn unknown_enum_values_are_preserved_as_integers() {
    // R7: a binary that knows fewer error codes than the writer must still be
    // able to read the file and report the number.
    let mut record = sample("tier_attempt");
    match record.event.as_mut().unwrap() {
        Event::TierAttempt(e) => {
            e.err = 99;
            e.err_code = 403;
        }
        other => panic!("wrong variant: {other:?}"),
    }

    assert!(ErrorCode::try_from(99).is_err(), "99 must be unknown here");
    let decoded = LogRecord::decode(record.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, record);

    match decoded.event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(e.err, 99);
            assert_eq!(e.err_code, 403);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // A code this build does know still resolves as one.
    match sample("tier_attempt").event.unwrap() {
        Event::TierAttempt(e) => {
            assert_eq!(ErrorCode::try_from(e.err), Ok(ErrorCode::TlsTimeout));
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn unset_error_fields_do_not_reach_the_wire() {
    let attempt = |err: ErrorCode, err_code: u32| {
        record(Event::TierAttempt(TierAttempt {
            tier: Tier::Ws as i32,
            dc: 2,
            is_media: false,
            ok: true,
            dur_ns: 120_000_000,
            err: i32::from(err),
            err_code,
        }))
    };

    // `ok` is held fixed so the difference is attributable to the error fields
    // alone — and `ok` is a bool, so it is itself omitted when false.
    let clean = attempt(ErrorCode::Unspecified, 0);
    let failed = attempt(ErrorCode::HttpRedirect, 302);

    // proto3 does not write a zero-valued scalar, so the successful attempt
    // pays for neither field: the difference is exactly `err = 7` (one-byte key,
    // one byte of value) and `err_code = 302` (one-byte key, two bytes).
    assert_eq!(
        failed.encoded_len() - clean.encoded_len(),
        5,
        "unset error fields must not reach the wire"
    );
}

#[test]
fn encoded_sizes_fit_the_storage_budget() {
    let mut sizes: Vec<(&'static str, usize)> = samples()
        .into_iter()
        .map(|(name, record)| (name, record.encoded_len()))
        .collect();
    sizes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));

    println!("encoded record size by variant:");
    for (name, size) in &sizes {
        println!("  {size:>4} B  {name}");
    }
    let total: usize = sizes.iter().map(|(_, s)| s).sum();
    println!("  {:>4} B  mean", total / sizes.len());

    let size_of = |name: &str| {
        sizes
            .iter()
            .find(|(n, _)| *n == name)
            .expect("sample exists")
            .1
    };

    // The budget in §1.2 of the plan: one record per session is what a day is
    // made of, and at 5 ev/s a day's worth has to stay inside the retention
    // estimate.
    assert!(
        size_of("session_closed") < 80,
        "session_closed grew to {} B",
        size_of("session_closed")
    );
    // A startup summary is the largest record by construction and is written
    // once per process; the ceiling keeps a future field from making the shape
    // of the file depend on the banner.
    assert!(
        size_of("startup_summary") < 512,
        "startup_summary grew to {} B",
        size_of("startup_summary")
    );
}

fn event_for(conn_id: u64, event: Event) -> LogRecord {
    LogRecord {
        conn_id,
        ..record(event)
    }
}
