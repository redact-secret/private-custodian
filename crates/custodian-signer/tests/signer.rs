//! The signer service over a real Unix socket, in-process, with synthetic
//! test keys generated inside each test.

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use common::cc::{self, projection, release_approval_json};
use common::*;
use custodian_contracts::approval::Approval;
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::SignatureAlgorithm;
use custodian_contracts::public::PublicProjectionEnvelope;
use custodian_contracts::revocation::SignedRevocationEnvelope;
use custodian_contracts::types::ExecutionId;
use custodian_ledger::{ApprovedPayload, SignDomain, SignRefusal, Signer};
use custodian_signer::frame;
use custodian_signer::{start, Reject, ServerError, SignerSetup};

fn approved_projection() -> ApprovedPayload {
    let approval: Approval = cc::parse(&release_approval_json());
    ApprovedPayload::projection(
        &projection(),
        &approval,
        &ExecutionId::parse(&cc::id("exe_", 1)).unwrap(),
        &cc::current(),
        cc::ts(NOW + 5),
        cc::MAX_AGE,
    )
    .unwrap()
}

fn reply(env: &Env, bytes: &[u8]) -> Result<Vec<u8>, Option<Reject>> {
    let mut s = env.raw();
    s.write_all(bytes).unwrap();
    frame::read_response(&mut s, Duration::from_secs(5))
}

fn framed(issued_at: u64, body: &[u8]) -> Vec<u8> {
    let mut v = header(
        b"PCSG",
        1,
        1,
        issued_at,
        u32::try_from(body.len()).unwrap(),
    );
    v.extend_from_slice(body);
    v
}

// ---- happy path --------------------------------------------------------------------

#[test]
fn signatures_over_the_socket_verify_under_the_public_key() {
    let env = Env::new();
    let engine = env.engine();
    let server = env.server(engine.clone());
    let client = env.client();
    let verifier = env.verifier(&engine);

    let signed = sign_record(&client, &checkpoint_record(NOW));
    assert_eq!(signed.signature.key_id, key_id());
    assert_eq!(signed.signature.algorithm, SignatureAlgorithm::Ed25519);
    verifier.verify_ledger_record(&signed).unwrap();

    let sig = client.sign(&approved_projection()).unwrap();
    verifier
        .verify_projection(&PublicProjectionEnvelope {
            payload: projection(),
            signature: sig,
        })
        .unwrap();

    let rev = ApprovedPayload::revocation(&cc::revocation()).unwrap();
    let sig = client.sign(&rev).unwrap();
    verifier
        .verify_revocation(&SignedRevocationEnvelope {
            payload: cc::revocation(),
            signature: sig,
        })
        .unwrap();

    // Ed25519 is deterministic, so a retry is byte-identical.
    let again = sign_record(&client, &checkpoint_record(NOW));
    assert_eq!(again.signature, signed.signature);
    assert_eq!(engine.stats().snapshot().signed, 4);
    server.shutdown();
}

// ---- refusals ----------------------------------------------------------------------

#[test]
fn the_signer_revalidates_and_refuses_wrong_domain_and_unapproved_payloads() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine.clone());
    let record = checkpoint_record(NOW).canonical_bytes().unwrap();
    let projection_bytes = projection().canonical_bytes().unwrap();
    let digest = projection().projection_digest().unwrap();

    let ask = |body: Vec<u8>| -> serde_json::Value {
        let bytes = reply(&env, &framed(T0, &body)).expect("framed reply");
        serde_json::from_slice(&bytes).unwrap()
    };
    let refused = |v: &serde_json::Value| v["refused"].as_str().unwrap().to_owned();

    // A store checkpoint presented as another ledger domain.
    let v = ask(wire(SignDomain::LedgerAuditEvent.tag(), &record, None));
    assert_eq!(refused(&v), "sign_wrong_domain");
    // A ledger record presented as a public projection.
    let v = ask(wire(SignDomain::PublicProjection.tag(), &record, None));
    assert!(["sign_payload_invalid", "sign_schema_mismatch"].contains(&refused(&v).as_str()));
    // An unknown domain.
    let v = ask(wire("private-custodian/v1/unknown", &record, None));
    assert_eq!(refused(&v), "sign_unknown_domain");
    // A real projection without its release approval digest, and with another.
    let v = ask(wire(
        SignDomain::PublicProjection.tag(),
        &projection_bytes,
        None,
    ));
    assert_eq!(refused(&v), "sign_not_approved");
    let other = cc::dg("some-other-projection");
    let v = ask(wire(
        SignDomain::PublicProjection.tag(),
        &projection_bytes,
        Some(&other),
    ));
    assert_eq!(refused(&v), "sign_not_approved");
    // Bytes that are not a document at all are never signed.
    let v = ask(wire(
        SignDomain::LedgerAuditEvent.tag(),
        b"raw bytes the client wants signed",
        None,
    ));
    assert!(v.get("signature").is_none());
    // Sanity: with the right digest the same projection is signed.
    let v = ask(wire(
        SignDomain::PublicProjection.tag(),
        &projection_bytes,
        Some(digest.as_str()),
    ));
    assert!(v.get("signature").is_some());
    let s = engine.stats().snapshot();
    assert_eq!((s.signed, s.refused), (1, 6));
}

#[test]
fn a_key_without_the_purpose_refuses_with_wrong_domain() {
    let env = Env::new();
    let mut setup = env.setup();
    setup.purposes = [SignDomain::LedgerAuditEvent].into_iter().collect();
    let _server = env.server(env.engine_with(setup));
    let client = env.client();
    assert_eq!(
        client.sign(&approved_projection()).unwrap_err(),
        SignRefusal::WrongDomain
    );
    assert_eq!(
        client
            .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
            .unwrap_err(),
        SignRefusal::WrongDomain
    );
}

#[test]
fn stale_payloads_and_stale_requests_are_refused() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine.clone());
    let client = env.client();
    let projection_payload = approved_projection();

    // Past the projection's `fresh_until` the signer will not sign it.
    env.clock.set(NOW + 40 + 86_400 + 1);
    assert_eq!(
        client.sign(&projection_payload).unwrap_err(),
        SignRefusal::NotApproved
    );
    assert_eq!(engine.stats().snapshot().stale_payload, 1);
    // Ledger records have no freshness of their own and still sign.
    client
        .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
        .unwrap();

    // A captured frame replayed later is stale at the transport.
    env.clock.set(T0);
    let body = wire(
        SignDomain::LedgerStoreCheckpoint.tag(),
        &checkpoint_record(NOW).canonical_bytes().unwrap(),
        None,
    );
    let captured = framed(T0, &body);
    assert!(reply(&env, &captured).is_ok());
    env.clock.set(T0 + 3600);
    assert_eq!(reply(&env, &captured), Err(Some(Reject::StaleRequest)));
    // A frame from the future is stale too.
    assert_eq!(
        reply(&env, &framed(T0 + 3600 + 3600, &body)),
        Err(Some(Reject::StaleRequest))
    );
}

#[test]
fn a_key_outside_its_window_does_not_sign() {
    let env = Env::new();
    let mut setup = env.setup();
    setup.valid_from = T0 + 10;
    setup.not_after = Some(T0 + 20);
    let engine = env.engine_with(setup);
    let _server = env.server(engine.clone());
    let client = env.client();
    let payload = ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap();

    // Before the window.
    assert_eq!(
        client.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    // Inside it.
    env.clock.set(T0 + 15);
    client.sign(&payload).unwrap();
    // At and after the end (retired).
    env.clock.set(T0 + 20);
    assert_eq!(
        client.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    let s = engine.stats().snapshot();
    assert_eq!((s.signed, s.key_out_of_window), (1, 2));
    assert!(env.event_text().contains("key_out_of_window"));
}

// ---- hostile and broken clients ----------------------------------------------------

fn assert_still_signs(env: &Env) {
    let signed = sign_record(&env.client(), &checkpoint_record(NOW));
    assert_eq!(signed.signature.key_id, key_id());
}

#[test]
fn malformed_oversize_and_wrong_version_frames_are_rejected_with_fixed_codes() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine.clone());

    assert_eq!(
        reply(&env, &header(b"XXXX", 1, 1, T0, 0)),
        Err(Some(Reject::Malformed))
    );
    assert_eq!(
        reply(&env, &header(b"PCSG", 2, 1, T0, 0)),
        Err(Some(Reject::UnsupportedVersion))
    );
    assert_eq!(
        reply(&env, &header(b"PCSG", 1, 9, T0, 0)),
        Err(Some(Reject::Malformed))
    );
    // Declared length over the limit is refused before any body is read.
    let too_big = u32::try_from(frame::MAX_BODY + 1).unwrap();
    assert_eq!(
        reply(&env, &header(b"PCSG", 1, 1, T0, too_big)),
        Err(Some(Reject::TooLarge))
    );
    assert_eq!(
        reply(&env, &header(b"PCSG", 1, 1, T0, u32::MAX)),
        Err(Some(Reject::TooLarge))
    );
    // A body that is not a wire request is a fixed payload refusal.
    let bytes = reply(&env, &framed(T0, b"CANARY-not-json")).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("sign_payload_invalid"));
    assert!(!text.contains("CANARY"));
    // Unknown fields are refused by the wire parser.
    let v = reply(&env, &framed(T0, br#"{"domain":"x","payload":"","extra":1}"#)).unwrap();
    assert!(String::from_utf8(v).unwrap().contains("sign_payload_invalid"));

    assert_eq!(engine.stats().snapshot().signed, 0);
    assert_still_signs(&env);
}

#[test]
fn truncated_requests_and_vanishing_clients_do_not_hurt_the_signer() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine.clone());

    // Header promises 100 bytes, 10 arrive, then the client closes.
    {
        let mut s = env.raw();
        let mut bytes = header(b"PCSG", 1, 1, T0, 100);
        bytes.extend_from_slice(&[b'x'; 10]);
        s.write_all(&bytes).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        // The signer answers with a fixed rejection (or just closes).
        let _ = frame::read_response(&mut s, Duration::from_secs(5));
    }
    // Half a header, then gone.
    {
        let mut s = env.raw();
        s.write_all(b"PCS").unwrap();
    }
    // Connect and vanish.
    drop(env.raw());
    assert!(wait_until(|| engine.stats().snapshot().rejected_frames >= 2));
    assert_eq!(engine.stats().snapshot().signed, 0);
    assert_still_signs(&env);
}

#[test]
fn a_slow_client_times_out_and_does_not_block_others() {
    let env = Env::new();
    let engine = env.engine();
    let mut cfg = env.server_config();
    cfg.io_timeout = Duration::from_millis(400);
    let _server = start(cfg, engine.clone()).unwrap();

    let mut slow = env.raw();
    slow.write_all(b"PCSG").unwrap(); // then silence
    let started = Instant::now();
    // While the slow client holds a slot, others are served immediately.
    assert_still_signs(&env);
    assert!(started.elapsed() < Duration::from_millis(300));
    // The slow client is cut off with the fixed timeout rejection.
    let r = frame::read_response(&mut slow, Duration::from_secs(5));
    assert_eq!(r, Err(Some(Reject::Timeout)));
    assert!(started.elapsed() < Duration::from_secs(3));

    // A trickling client cannot extend the deadline by sending one byte at a time.
    let mut drip = env.raw();
    let started = Instant::now();
    let h = header(b"PCSG", 1, 1, T0, 0);
    for b in h {
        if drip.write_all(&[b]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(60));
    }
    let r = frame::read_response(&mut drip, Duration::from_secs(5));
    assert_eq!(r, Err(Some(Reject::Timeout)));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_slow_or_silent_signer_fails_the_client_closed_within_its_timeout() {
    let env = Env::new();
    let listener = UnixListener::bind(&env.sock).unwrap();
    let hold = std::thread::spawn(move || {
        // Accept, read nothing, answer nothing, keep the connection open.
        let (s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        drop(s);
    });
    let client = custodian_ledger::RemoteSigner::new(
        key_id(),
        custodian_signer::UnixSocketTransport::new(env.sock.clone(), Duration::from_millis(300)),
    );
    let started = Instant::now();
    assert_eq!(
        client
            .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
            .unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    assert!(started.elapsed() < Duration::from_millis(1400));
    hold.join().unwrap();
}

#[test]
fn a_hostile_signer_cannot_feed_the_client_garbage_or_oversize_frames() {
    let env = Env::new();
    let listener = UnixListener::bind(&env.sock).unwrap();
    let t = std::thread::spawn(move || {
        for reply in [
            b"PCSR\x01\x00\xff\xff\xff\xff".to_vec(), // oversize length
            b"not a frame at all".to_vec(),
            b"PCSR\x02\x00\x00\x00\x00\x00".to_vec(), // wrong version
            b"PCSR\x01\x00\x00\x00\x00\x02{}".to_vec(), // ok frame, junk body
        ] {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(&reply);
        }
    });
    let client = env.client();
    let payload = ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap();
    for _ in 0..4 {
        assert_eq!(
            client.sign(&payload).unwrap_err(),
            SignRefusal::SignerUnavailable
        );
    }
    t.join().unwrap();
}

// ---- crash, restart, absence ------------------------------------------------------

#[test]
fn signer_crash_and_restart_fail_closed_then_recover() {
    let env = Env::new();
    let engine = env.engine();
    let payload = ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap();
    let client = env.client();

    // Not running yet: nothing is signed.
    assert_eq!(
        client.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );

    let server = env.server(engine.clone());
    let first = client.sign(&payload).unwrap();
    // "Crash": the listener goes away without the shutdown path having run its
    // cleanup of the socket file (simulate with a leftover socket inode).
    server.shutdown();
    drop(UnixListener::bind(&env.sock).unwrap()); // leaves a stale socket file
    assert!(env.sock.exists());
    assert_eq!(
        client.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );

    // Restart reclaims the stale socket and signs identically.
    let _server = env.server(env.engine());
    assert_eq!(client.sign(&payload).unwrap(), first);
}

#[test]
fn the_client_refuses_a_server_running_as_another_uid() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine);
    let me = custodian_signer::effective_uid();
    let payload = ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap();
    let ok = custodian_ledger::RemoteSigner::new(
        key_id(),
        env.transport().expecting_signer_uid(me),
    );
    ok.sign(&payload).unwrap();
    let wrong = custodian_ledger::RemoteSigner::new(
        key_id(),
        env.transport().expecting_signer_uid(me.wrapping_add(1)),
    );
    assert_eq!(
        wrong.sign(&payload).unwrap_err(),
        SignRefusal::SignerUnavailable
    );
}

// ---- peer credentials, socket and directory permissions ------------------------------

#[test]
fn only_the_allowed_peer_uid_is_served() {
    let env = Env::new();
    let engine = env.engine();
    let mut cfg = env.server_config();
    cfg.allowed_peer_uid = custodian_signer::effective_uid().wrapping_add(1);
    let _server = start(cfg, engine.clone()).unwrap();

    let body = wire(
        SignDomain::LedgerStoreCheckpoint.tag(),
        &checkpoint_record(NOW).canonical_bytes().unwrap(),
        None,
    );
    assert_eq!(
        reply(&env, &framed(T0, &body)),
        Err(Some(Reject::PeerDenied))
    );
    assert_eq!(
        env.client()
            .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
            .unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    assert_eq!(engine.stats().snapshot().signed, 0);
    assert!(env.event_text().contains("peer_denied"));
}

#[test]
fn socket_and_directory_permissions_are_enforced() {
    let env = Env::new();
    let engine = env.engine();
    let server = env.server(engine.clone());
    let mode = std::fs::symlink_metadata(&env.sock)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "socket is owner-only");

    // A second signer on the same path is refused while the first lives.
    assert_eq!(
        start(env.server_config(), engine.clone()).unwrap_err(),
        ServerError::AlreadyRunning
    );
    server.shutdown();
    assert!(!env.sock.exists(), "shutdown removes the socket");

    // A directory open to group or other is refused.
    std::fs::set_permissions(&env.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        start(env.server_config(), engine.clone()).unwrap_err(),
        ServerError::SocketDirectoryInsecure
    );
    std::fs::set_permissions(&env.root, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        start(env.server_config(), engine.clone()).unwrap_err(),
        ServerError::SocketDirectoryInsecure
    );
    std::fs::set_permissions(&env.root, std::fs::Permissions::from_mode(0o700)).unwrap();

    // A regular file at the socket path is not removed or replaced.
    std::fs::write(&env.sock, b"not a socket").unwrap();
    assert_eq!(
        start(env.server_config(), engine.clone()).unwrap_err(),
        ServerError::SocketPathOccupied
    );
    assert_eq!(std::fs::read(&env.sock).unwrap(), b"not a socket");
    std::fs::remove_file(&env.sock).unwrap();

    // A symlinked directory is refused.
    let link = std::env::temp_dir().join(format!("pcsg-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&env.root, &link).unwrap();
    let mut cfg = env.server_config();
    cfg.socket_path = link.join("s");
    assert_eq!(
        start(cfg, engine).unwrap_err(),
        ServerError::SocketDirectoryInsecure
    );
    let _ = std::fs::remove_file(&link);
}

// ---- concurrency ------------------------------------------------------------------

#[test]
fn concurrent_clients_all_get_valid_signatures() {
    let env = Env::new();
    let engine = env.engine();
    let _server = env.server(engine.clone());
    let verifier = env.verifier(&engine);
    let handles: Vec<_> = (0..6u64)
        .map(|i| {
            let client = env.client();
            std::thread::spawn(move || {
                (0..5u64)
                    .map(|j| sign_record(&client, &checkpoint_record(NOW + i * 10 + j)))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut n = 0;
    for h in handles {
        for signed in h.join().unwrap() {
            verifier.verify_ledger_record(&signed).unwrap();
            n += 1;
        }
    }
    assert_eq!(n, 30);
    assert_eq!(engine.stats().snapshot().signed, 30);
}

#[test]
fn concurrency_is_bounded_and_overflow_fails_closed_without_blocking() {
    let env = Env::new();
    let engine = env.engine();
    let mut cfg = env.server_config();
    cfg.max_concurrent = 1;
    cfg.io_timeout = Duration::from_millis(1500);
    let _server = start(cfg, engine.clone()).unwrap();

    let mut hog = env.raw();
    hog.write_all(b"PCSG").unwrap(); // holds the only slot
    std::thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    assert_eq!(
        env.client()
            .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
            .unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    assert!(started.elapsed() < Duration::from_millis(800));
    assert!(env.event_text().contains("signer_busy"));
    // Once the hog is cut off the slot frees up.
    let _ = frame::read_response(&mut hog, Duration::from_secs(5));
    assert!(wait_until(|| env
        .client()
        .sign(&ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap())
        .is_ok()));
}

// ---- no key material anywhere an observer could see it ---------------------------------

#[test]
fn no_key_material_or_payload_text_appears_in_responses_events_errors_or_debug() {
    let env = Env::new();
    let engine = env.engine();
    let server = env.server(engine.clone());
    let client = env.client();
    let mut seen = String::new();

    // Success, refusals and abuse.
    let payload = ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap();
    seen.push_str(&format!("{:?}", client.sign(&payload)));
    for body in [
        wire("CANARY-domain", b"CANARY-payload", None),
        wire(SignDomain::LedgerPolicy.tag(), b"CANARY-payload", None),
        b"CANARY-garbage".to_vec(),
    ] {
        match reply(&env, &framed(T0, &body)) {
            Ok(b) => seen.push_str(&String::from_utf8_lossy(&b)),
            Err(e) => seen.push_str(&format!("{e:?}")),
        }
    }
    for h in [
        header(b"XXXX", 1, 1, T0, 0),
        header(b"PCSG", 1, 1, T0, u32::MAX),
    ] {
        seen.push_str(&format!("{:?}", reply(&env, &h)));
    }
    seen.push_str(&env.event_text());
    seen.push_str(&format!("{engine:?} {server:?} {:?}", env.transport()));
    for r in Reject::ALL {
        seen.push_str(&format!("{r} {r:?}"));
    }
    seen.push_str(&format!(
        "{:?}",
        custodian_signer::FileKeyProvider::new(env.key_path.clone())
    ));
    let seed = custodian_signer::FileKeyProvider::new(env.key_path.clone())
        .load_seed()
        .unwrap();
    seen.push_str(&format!("{seed:?}"));

    assert!(!seen.contains(&env.seed_hex), "seed leaked");
    assert!(!seen.contains(&path_str(&env.key_path)), "key path leaked");
    assert!(!seen.contains(&path_str(&env.sock)), "socket path leaked");
    assert!(!seen.contains("CANARY"), "client text echoed");
    assert!(seen.contains("redacted"));
}

use custodian_signer::KeyProvider;

#[test]
fn setup_struct_is_plain_data() {
    // Guards the public shape S5 and S6 rely on.
    let env = Env::new();
    let s: SignerSetup = env.setup();
    assert_eq!(s.purposes.len(), SignDomain::ALL.len());
}
