use crate::constants::*;
use log::warn;
use reqwest::Client;
use std::{sync::Arc, time::SystemTime};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct ModelInfo {
    pub id: String,
    pub input_price_usd: Option<f64>,
    pub output_price_usd: Option<f64>,
    pub supported_features: Vec<String>,
}

// ---------- App with cached models and circuit breaker ----------

#[derive(Clone)]
pub struct App {
    pub client: Client,
    pub backend_url: String,
    pub backend_host_header: Option<String>,
    pub models_cache: Arc<RwLock<Option<Vec<ModelInfo>>>>,
    pub circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
}

// ---------- Circuit breaker state ----------

#[derive(Clone, Debug)]
pub struct CircuitBreakerState {
    pub consecutive_failures: u32,
    pub last_failure_time: Option<SystemTime>,
    pub is_open: bool,
    pub enabled: bool,
}

impl CircuitBreakerState {
    pub fn new(enabled: bool) -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_time: None,
            is_open: false,
            enabled,
        }
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.is_open = false;
        self.last_failure_time = None;
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure_time = Some(SystemTime::now());
        if self.consecutive_failures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            self.is_open = true;
            warn!(
                "🔴 Circuit breaker opened after {} consecutive failures",
                self.consecutive_failures
            );
        }
    }

    pub fn should_allow_request(&mut self) -> bool {
        if !self.enabled {
            return true;
        }
        if !self.is_open {
            return true;
        }
        // Try to recover after 30 seconds
        if let Some(last_fail) = self.last_failure_time {
            if let Ok(elapsed) = SystemTime::now().duration_since(last_fail) {
                if elapsed.as_secs() >= 30 {
                    log::info!("🟡 Circuit breaker attempting half-open state");
                    self.is_open = false;
                    self.consecutive_failures = 0;
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_circuit_breaker_starts_closed() {
        let breaker = CircuitBreakerState::new(true);
        assert!(!breaker.is_open);
        assert_eq!(breaker.consecutive_failures, 0);
        assert!(breaker.enabled);
    }

    #[test]
    fn test_circuit_breaker_record_success_resets_state() {
        let mut breaker = CircuitBreakerState::new(true);
        breaker.consecutive_failures = 3;
        breaker.is_open = true;
        breaker.last_failure_time = Some(SystemTime::now());

        breaker.record_success();

        assert_eq!(breaker.consecutive_failures, 0);
        assert!(!breaker.is_open);
        assert!(breaker.last_failure_time.is_none());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold_failures() {
        let mut breaker = CircuitBreakerState::new(true);
        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }

        assert!(breaker.is_open);
        assert_eq!(
            breaker.consecutive_failures,
            CIRCUIT_BREAKER_FAILURE_THRESHOLD
        );
    }

    #[test]
    fn test_circuit_breaker_disabled_always_allows_request() {
        let mut breaker = CircuitBreakerState::new(false);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;

        assert!(breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_blocks_request_while_open_before_timeout() {
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now());

        assert!(!breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_recovers_after_timeout() {
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now() - Duration::from_secs(31));

        assert!(breaker.should_allow_request());
        assert!(!breaker.is_open);
        assert_eq!(breaker.consecutive_failures, 0);
    }

    #[test]
    fn test_circuit_breaker_allows_request_when_enabled_but_closed() {
        // Line 69: enabled && !is_open → return true
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = false;

        assert!(breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open_and_no_failure_time() {
        // Line 80: enabled, open, but last_failure_time is None → false
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.last_failure_time = None;

        assert!(!breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open_and_timeout_not_elapsed() {
        // Line 80: enabled, open, recent failure time → false
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now() - Duration::from_secs(10));

        assert!(!breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_blocks_when_failure_time_in_future() {
        // Line 80: enabled, open, last_failure_time in the future → duration_since
        // returns Err → the `if let Ok(elapsed)` false branch is taken → falls to false.
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now() + Duration::from_secs(60));

        assert!(!breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_record_failure_increments_and_sets_time() {
        let mut breaker = CircuitBreakerState::new(true);
        assert!(breaker.last_failure_time.is_none());

        breaker.record_failure();

        assert_eq!(breaker.consecutive_failures, 1);
        assert!(breaker.last_failure_time.is_some());
        assert!(!breaker.is_open); // only 1 failure, below threshold
    }

    #[test]
    fn test_circuit_breaker_record_failure_below_threshold_does_not_open() {
        let mut breaker = CircuitBreakerState::new(true);
        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD - 1 {
            breaker.record_failure();
        }

        assert!(!breaker.is_open);
        assert_eq!(
            breaker.consecutive_failures,
            CIRCUIT_BREAKER_FAILURE_THRESHOLD - 1
        );
    }

    #[test]
    fn test_circuit_breaker_new_disabled() {
        let breaker = CircuitBreakerState::new(false);
        assert!(!breaker.enabled);
        assert!(!breaker.is_open);
        assert_eq!(breaker.consecutive_failures, 0);
        assert!(breaker.last_failure_time.is_none());
    }
    #[test]
    fn test_circuit_breaker_record_failure_disabled_still_increments() {
        // Even when disabled, record_failure increments failures and can set is_open
        // at threshold. This is the battle test issue 2.1: the breaker records
        // failures regardless of enabled state, but should_allow_request short-
        // circuits to true when disabled, and health_check reports healthy.
        let mut breaker = CircuitBreakerState::new(false);
        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }
        assert_eq!(
            breaker.consecutive_failures,
            CIRCUIT_BREAKER_FAILURE_THRESHOLD
        );
        assert!(breaker.is_open); // is_open set even when disabled
        assert!(!breaker.enabled);
    }

    #[test]
    fn test_circuit_breaker_disabled_open_still_allows_request() {
        let mut breaker = CircuitBreakerState::new(false);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now());
        // Even with is_open=true, disabled breaker allows all requests
        assert!(breaker.should_allow_request());
    }

    #[test]
    fn test_circuit_breaker_record_success_on_disabled_breaker() {
        let mut breaker = CircuitBreakerState::new(false);
        breaker.consecutive_failures = 10;
        breaker.is_open = true;
        breaker.last_failure_time = Some(SystemTime::now());
        breaker.record_success();
        assert_eq!(breaker.consecutive_failures, 0);
        assert!(!breaker.is_open);
        assert!(breaker.last_failure_time.is_none());
    }

    #[test]
    fn test_circuit_breaker_record_failure_logs_warning_at_threshold() {
        // The warn! format argument (self.consecutive_failures) is only
        // evaluated when logging is enabled. Install the test logger so the
        // argument line is executed and counted.
        crate::test_log::init_test_logger();
        let mut breaker = CircuitBreakerState::new(true);
        for _ in 0..CIRCUIT_BREAKER_FAILURE_THRESHOLD {
            breaker.record_failure();
        }
        assert!(breaker.is_open);
    }

    #[test]
    fn test_circuit_breaker_half_open_logs_info_on_recovery() {
        // The info! log on half-open recovery is only evaluated when logging
        // is enabled.
        crate::test_log::init_test_logger();
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now() - Duration::from_secs(31));
        assert!(breaker.should_allow_request());
        assert!(!breaker.is_open);
    }

    #[test]
    fn test_circuit_breaker_blocks_when_failure_time_is_in_future() {
        // If last_failure_time is ahead of now (clock skew), duration_since
        // returns Err, so the recovery if-let-Ok is skipped and the request
        // is blocked. Covers the not-Ok path of the elapsed check.
        let mut breaker = CircuitBreakerState::new(true);
        breaker.is_open = true;
        breaker.consecutive_failures = CIRCUIT_BREAKER_FAILURE_THRESHOLD;
        breaker.last_failure_time = Some(SystemTime::now() + Duration::from_secs(60));

        assert!(!breaker.should_allow_request());
    }
}
