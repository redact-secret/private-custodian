//! C12 control-plane measurements. Run with
//! `cargo run --release -p custodian-cli --example c12_measure` (optionally
//! `C12_MEASURE_N=200`). Prints markdown tables. Nothing here is a pass/fail
//! threshold and nothing is asserted about speed: the numbers are a
//! description of one machine on one day, recorded in docs/measurements.md
//! with their method.
//!
//! What is measured: the custodian control plane only (CLI commands, SQLite
//! store, in-memory ledger backend, audit export). What is NOT measured and
//! must not be inferred: scanner or kernel speed, sandbox startup, engine
//! time, a real Git ledger remote, network latency, or a real signer process.
//! Isolation is never relaxed, audit writes are never skipped and budgets are
//! never reset to improve a number: every command runs its full path,
//! including the startup check against the whole ledger.
//!
//! Synthetic data and test-generated keys only.

#[path = "../tests/c12/mod.rs"]
mod c12;

use std::thread;
use std::time::Instant;

use c12::*;
use custodian_cli::command::{RepairCommand, VerifyTarget};
use custodian_cli::{Command, Control};
use custodian_intake::ids::{
    DeliveryId, GithubUserId, HeadSha, InstallationId, PullRequestNumber, RepositoryId,
};
use custodian_intake::ports::{DeliveryStore, IntakeQueue, QueuedRequest};
use custodian_store::SqliteStore;

fn n_from_env(default: usize) -> usize {
    std::env::var("C12_MEASURE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn pct(v: &mut [f64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() as f64 - 1.0) * q).round() as usize;
    v[i]
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn row(label: &str, v: &mut [f64]) -> String {
    format!(
        "| {label} | {} | {:.2} | {:.2} | {:.2} |",
        v.len(),
        pct(v, 0.5),
        pct(v, 0.95),
        pct(v, 1.0)
    )
}

/// Request latency by operation, with the audit ledger growing between
/// batches (each batch is exported before the next, so the startup check that
/// every state-changing command runs walks a larger ledger).
pub fn request_latency(batches: usize, per_batch: usize) -> Vec<String> {
    let p = Pipe::new(1_000_000, 4);
    let mut out = vec![
        "| operation (ledger records before the batch) | n | p50 ms | p95 ms | max ms |".to_owned(),
        "| --- | --- | --- | --- | --- |".to_owned(),
    ];
    let mut n = 0u32;
    for b in 0..batches {
        let records = p.w.ledger.file_count();
        let (mut sub, mut app, mut stat) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..per_batch {
            n += 1;
            let t = Instant::now();
            let s = p.submit(n);
            sub.push(ms(t.elapsed()));
            assert!(s.is_ok());
            let t = Instant::now();
            let a = p.approve(n);
            app.push(ms(t.elapsed()));
            assert!(a.is_ok());
            let (req, _) = p.request(n);
            let t = Instant::now();
            let _ = p.w.run(Who::Requester, &c12::base::status_cmd(&req));
            stat.push(ms(t.elapsed()));
        }
        out.push(row(
            &format!("submit ({records} records, batch {b})"),
            &mut sub,
        ));
        out.push(row(
            &format!("approve ({records} records, batch {b})"),
            &mut app,
        ));
        out.push(row(
            &format!("status ({records} records, batch {b})"),
            &mut stat,
        ));
        let t = Instant::now();
        let e = p.export();
        assert!(e.is_ok());
        let exp = ms(t.elapsed());
        let t = Instant::now();
        let v = p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All));
        out.push(format!(
            "| export of the batch / `verify all` after it | 1 | {exp:.2} / {:.2} | | |",
            ms(t.elapsed())
        ));
        assert_eq!(v.code(), "verified");
    }
    out
}

/// Approvals of distinct requests from several connections at once.
pub fn db_contention(thread_counts: &[usize], per_thread: usize) -> Vec<String> {
    let mut out = vec![
        "| threads | approvals | approved | refused (code: count) | wall ms | approvals/s |"
            .to_owned(),
        "| --- | --- | --- | --- | --- | --- |".to_owned(),
    ];
    for &threads in thread_counts {
        let total = threads * per_thread;
        let p = Pipe::new(1_000_000, 4);
        for n in 1..=total as u32 {
            assert!(p.submit(n).is_ok());
        }
        let p = &p;
        let t0 = Instant::now();
        let codes: Vec<&'static str> = thread::scope(|s| {
            let hs: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        let store = SqliteStore::open(p.w.rw.db.path()).unwrap();
                        let mut out = Vec::new();
                        for i in 0..per_thread {
                            let n = (t * per_thread + i + 1) as u32;
                            let (req, _) = p.request(n);
                            let mut parts = p.w.parts();
                            parts.store = &store;
                            let o = Control::new(parts).execute(
                                &p.w.principal(Who::Approver),
                                &approve_cmd(&req),
                                false,
                            );
                            out.push(o.code());
                        }
                        out
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        let wall = t0.elapsed();
        let approved = codes.iter().filter(|c| **c == "approved").count();
        let mut refused: std::collections::BTreeMap<&str, usize> = Default::default();
        for c in codes.iter().filter(|c| **c != "approved") {
            *refused.entry(c).or_default() += 1;
        }
        out.push(format!(
            "| {threads} | {total} | {approved} | {refused:?} | {:.0} | {:.1} |",
            ms(wall),
            total as f64 / wall.as_secs_f64()
        ));
        assert_eq!(
            p.w.budget().held,
            approved as u64,
            "nothing lost or doubled"
        );
    }
    out
}

fn queued(n: u64) -> QueuedRequest {
    QueuedRequest {
        delivery: DeliveryId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap(),
        installation: InstallationId::new(900_001).unwrap(),
        repository: RepositoryId::new(800_001).unwrap(),
        pull_request: PullRequestNumber::new(7).unwrap(),
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        actor: custodian_contracts::types::ActorRef::parse(&cc::id("act_", 1)).unwrap(),
        github_user: GithubUserId::new(700_001).unwrap(),
        received_at: ts(NOW),
    }
}

/// Queue and pending-submission limits, and the cost of filling toward them.
pub fn queue_limits(enqueue_n: usize, submit_n: usize) -> Vec<String> {
    let p = Pipe::new(1_000_000, 4);
    let mut out = vec![
        "| measure | value |".to_owned(),
        "| --- | --- |".to_owned(),
        format!(
            "| intake queue capacity (MAX_PENDING_QUEUE) | {} |",
            custodian_store::MAX_PENDING_QUEUE
        ),
        format!(
            "| pending submissions capacity (MAX_PENDING_SUBMISSIONS) | {} |",
            custodian_store::MAX_PENDING_SUBMISSIONS
        ),
    ];
    let mut lat = Vec::new();
    for i in 0..enqueue_n {
        let id = i as u64 + 1;
        let d = DeliveryId::parse(&format!("00000000-0000-4000-8000-{id:012x}")).unwrap();
        let t = Instant::now();
        p.w.rw.store.claim(&d).unwrap();
        p.w.rw.store.enqueue(queued(id)).unwrap();
        lat.push(ms(t.elapsed()));
    }
    out.push(format!(
        "| claim+enqueue latency over {enqueue_n} deliveries, p50/p95/max ms | {:.2} / {:.2} / {:.2} |",
        pct(&mut lat, 0.5),
        pct(&mut lat, 0.95),
        pct(&mut lat, 1.0)
    ));
    out.push(format!(
        "| queue depth after | {} |",
        p.w.rw.store.queue_depth().unwrap()
    ));
    let mut codes: std::collections::BTreeMap<&str, usize> = Default::default();
    let t0 = Instant::now();
    for n in 1..=submit_n as u32 {
        let o = p.submit(n);
        *codes.entry(o.code()).or_default() += 1;
    }
    out.push(format!(
        "| {submit_n} submissions, codes | {codes:?} in {:.0} ms |",
        ms(t0.elapsed())
    ));
    out
}

/// Growth of the ledger export and of whole-ledger verification.
pub fn export_growth(sizes: &[usize]) -> Vec<String> {
    let mut out = vec![
        "| reservations exported | audit events | ledger files | ledger bytes | export ms | ms/event | `verify all` ms |".to_owned(),
        "| --- | --- | --- | --- | --- | --- | --- |".to_owned(),
    ];
    for &k in sizes {
        let p = Pipe::new(1_000_000, 4);
        for n in 1..=k as u32 {
            assert!(p.submit(n).is_ok());
            assert!(p.approve(n).is_ok());
        }
        let events = p.w.rw.store.outbox_pending_count().unwrap();
        let t = Instant::now();
        let e = p.export();
        assert!(e.is_ok(), "{}", e.render());
        let export = ms(t.elapsed());
        let files = p.w.ledger.file_count();
        let bytes: usize =
            p.w.ledger
                .paths()
                .iter()
                .map(|f| p.w.ledger.raw(f).map(|b| b.len()).unwrap_or(0))
                .sum();
        let t = Instant::now();
        let v = p.w.run(Who::Auditor, &Command::Verify(VerifyTarget::All));
        let verify = ms(t.elapsed());
        assert_eq!(v.code(), "verified");
        out.push(format!(
            "| {k} | {events} | {files} | {bytes} | {export:.1} | {:.3} | {verify:.1} |",
            export / events.max(1) as f64
        ));
        // A repeat export finds nothing to do.
        let t = Instant::now();
        let again = p.w.run(
            Who::Operator,
            &Command::Repair(RepairCommand::Export {
                confirm_store_id: p.w.rw.store.store_id().unwrap(),
            }),
        );
        let _ = (again, t);
    }
    out
}

fn main() {
    let n = n_from_env(40);
    println!("## Request latency (control plane only)\n");
    for l in request_latency(3, n) {
        println!("{l}");
    }
    println!("\n## Database contention (approvals on separate connections)\n");
    for l in db_contention(&[1, 2, 4, 8], n.max(8) / 2) {
        println!("{l}");
    }
    println!("\n## Queue and submission limits\n");
    for l in queue_limits(n * 10, n) {
        println!("{l}");
    }
    println!("\n## Ledger export growth\n");
    for l in export_growth(&[n / 2, n, n * 2, n * 4]) {
        println!("{l}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measurement code itself runs and reports consistent counts at a
    /// tiny size. No timing is asserted.
    #[test]
    fn measurements_run_and_stay_consistent_at_a_tiny_size() {
        assert!(request_latency(2, 3).len() > 6);
        assert!(db_contention(&[1, 2], 3).len() == 4);
        assert!(queue_limits(5, 5).len() > 5);
        assert!(export_growth(&[2, 4]).len() == 4);
    }
}
