//! In-process background jobs for long-running operations.
//!
//! Carving a large drive can take an hour, which does not fit a single
//! synchronous MCP `tools/call` (the server would block and the client would
//! time out). A job runs on a worker thread, exposes live progress, and can be
//! cancelled, so the MCP server stays responsive and an agent polls for
//! completion instead of waiting on one call.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::carver::ProgressSink;
use crate::json::{obj, s, Json};

/// Shared, thread-safe state for one running job. It doubles as the carver's
/// [`ProgressSink`], so the worker reports bytes scanned and observes
/// cancellation through the same object the registry exposes to status queries.
pub struct Progress {
    kind: &'static str,
    total: AtomicU64,
    scanned: AtomicU64,
    done: AtomicBool,
    cancel: AtomicBool,
    result: Mutex<Option<Result<Json, String>>>,
}

impl Progress {
    fn new(kind: &'static str) -> Self {
        Progress {
            kind,
            total: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            done: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            result: Mutex::new(None),
        }
    }
}

impl ProgressSink for Progress {
    fn begin(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }
    fn update(&self, scanned: u64) {
        self.scanned.store(scanned, Ordering::Relaxed);
    }
    fn finish(&self, scanned: u64) {
        self.scanned.store(scanned, Ordering::Relaxed);
    }
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

struct Registry {
    next: u64,
    jobs: HashMap<u64, Arc<Progress>>,
}

fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            jobs: HashMap::new(),
        })
    })
}

/// Start a background job. `work` receives the shared [`Progress`] (pass it as
/// the carver's `ProgressSink`) and returns the job's result value. Returns the
/// new job id.
pub fn start<F>(kind: &'static str, work: F) -> u64
where
    F: FnOnce(&Progress) -> Result<Json, String> + Send + 'static,
{
    let prog = Arc::new(Progress::new(kind));
    let id = {
        let mut r = registry().lock().unwrap();
        let id = r.next;
        r.next += 1;
        r.jobs.insert(id, Arc::clone(&prog));
        id
    };
    std::thread::spawn(move || {
        let res = work(&prog);
        *prog.result.lock().unwrap() = Some(res);
        prog.done.store(true, Ordering::Release);
    });
    id
}

/// Snapshot a job's status (including its result once finished). Returns `None`
/// if there is no job with that id.
pub fn status(id: u64) -> Option<Json> {
    let prog = registry().lock().unwrap().jobs.get(&id).cloned()?;
    let done = prog.done.load(Ordering::Acquire);
    let mut fields = vec![
        ("job_id", Json::Num(id as f64)),
        ("kind", s(prog.kind)),
        ("running", Json::Bool(!done)),
        (
            "cancel_requested",
            Json::Bool(prog.cancel.load(Ordering::Relaxed)),
        ),
        (
            "bytes_scanned",
            Json::Num(prog.scanned.load(Ordering::Relaxed) as f64),
        ),
        (
            "bytes_total",
            Json::Num(prog.total.load(Ordering::Relaxed) as f64),
        ),
    ];
    if done {
        match prog.result.lock().unwrap().as_ref() {
            Some(Ok(value)) => fields.push(("result", value.clone())),
            Some(Err(msg)) => fields.push(("error", s(msg.clone()))),
            None => {}
        }
    }
    Some(obj(fields))
}

/// Request cancellation of a job. Returns whether the job exists.
pub fn cancel(id: u64) -> bool {
    match registry().lock().unwrap().jobs.get(&id) {
        Some(prog) => {
            prog.cancel.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_done(id: u64) -> Json {
        for _ in 0..1000 {
            let st = status(id).unwrap();
            if !st.get("running").unwrap().as_bool().unwrap() {
                return st;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("job {id} did not finish");
    }

    #[test]
    fn runs_a_job_to_completion() {
        let id = start("test", |p| {
            p.begin(10);
            p.update(10);
            Ok(obj(vec![("answer", Json::Num(42.0))]))
        });
        let st = wait_done(id);
        assert_eq!(st.get("kind").unwrap().as_str(), Some("test"));
        assert_eq!(st.get("bytes_total").unwrap().as_u64(), Some(10));
        assert_eq!(
            st.get("result").unwrap().get("answer").unwrap().as_u64(),
            Some(42)
        );
    }

    #[test]
    fn reports_errors() {
        let id = start("test", |_| Err("boom".to_string()));
        let st = wait_done(id);
        assert_eq!(st.get("error").unwrap().as_str(), Some("boom"));
    }

    #[test]
    fn cancellation_is_observed() {
        let id = start("test", |p| {
            // Spin until cancelled (bounded so a stuck test still ends).
            for _ in 0..100_000 {
                if p.cancelled() {
                    return Ok(obj(vec![("cancelled", Json::Bool(true))]));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Ok(obj(vec![("cancelled", Json::Bool(false))]))
        });
        assert!(cancel(id));
        let st = wait_done(id);
        assert_eq!(
            st.get("result")
                .unwrap()
                .get("cancelled")
                .unwrap()
                .as_bool(),
            Some(true)
        );
    }

    #[test]
    fn unknown_job_is_none() {
        assert!(status(9_999_999).is_none());
        assert!(!cancel(9_999_999));
    }
}
