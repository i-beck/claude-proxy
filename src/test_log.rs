//! Test-only helper that registers a no-op global logger so that `log::` macro
//! format arguments are evaluated (and thus counted for coverage) even when no
//! real logger backend is initialised.
//!
//! `log::warn!`, `log::info!`, etc. short-circuit: they only build the record
//! (and evaluate the format arguments) when `log_enabled!` returns true. With
//! no logger registered, `log_enabled!` is always false, so argument
//! expressions such as `self.consecutive_failures` (app.rs) and `other`
//! (content_extraction.rs) are never executed and show as uncovered. This
//! helper installs a logger whose `enabled()` returns true and bumps the max
//! level, making those argument lines execute during tests.

#[cfg(test)]
use std::sync::Once;

#[cfg(test)]
static LOG_INIT: Once = Once::new();

#[cfg(test)]
struct NoopLogger;

#[cfg(test)]
impl log::Log for NoopLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, _record: &log::Record) {}
    fn flush(&self) {}
}

/// Idempotently install the no-op test logger. Safe to call from any test.
#[cfg(test)]
pub fn init_test_logger() {
    LOG_INIT.call_once(|| {
        static NOOP: NoopLogger = NoopLogger;
        // set_logger can only succeed once per process; ignore the error if a
        // logger was already registered by another test.
        let _ = log::set_logger(&NOOP);
        log::set_max_level(log::LevelFilter::Trace);
    });
}
