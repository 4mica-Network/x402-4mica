use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Url;
use rust_sdk_4mica::{BLSCert, U256};
use serde::Deserialize;
use tokio::sync::{Mutex as TokioMutex, OwnedMutexGuard};

use crate::issuer::parse_error_message;

#[async_trait]
pub trait RequestIdTracker: Send + Sync {
    async fn reserve(
        &self,
        tab_id: U256,
        claimed_req_id: U256,
        claimed_timestamp: u64,
    ) -> Result<RequestIdReservation, RequestIdError>;

    async fn fetch_certificate(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> Result<Option<BLSCert>, RequestIdError>;
}

pub struct LiveRequestIdTracker {
    client: reqwest::Client,
    base_url: Url,
    locks: TokioMutex<HashMap<U256, Arc<TokioMutex<TabState>>>>,
}

impl LiveRequestIdTracker {
    pub fn new(base_url: Url) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            locks: TokioMutex::new(HashMap::new()),
        }
    }

    async fn acquire_lock(&self, tab_id: U256) -> Arc<TokioMutex<TabState>> {
        let mut locks = self.locks.lock().await;
        locks
            .entry(tab_id)
            .or_insert_with(|| Arc::new(TokioMutex::new(TabState::default())))
            .clone()
    }

    async fn determine_initial(&self, tab_id: U256) -> Result<InitialState, RequestIdError> {
        let mut url = self.base_url.clone();
        url.set_path(&format!("core/tabs/{}/guarantees", format!("{tab_id:#x}")));

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))?;

        if !status.is_success() {
            let message = parse_error_message(&bytes);
            return Err(RequestIdError::fetch(
                tab_id,
                format!("status {status}: {message}"),
            ));
        }

        let guarantees: Vec<GuaranteeRecord> = serde_json::from_slice(&bytes)
            .map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))?;

        let count = guarantees.len();
        let count_u64 = u64::try_from(count)
            .map_err(|_| RequestIdError::fetch(tab_id, "too many guarantees".into()))?;
        let start_timestamp = guarantees
            .first()
            .map(|record| record.start_timestamp)
            .map(|value| {
                if value < 0 {
                    Err(RequestIdError::InvalidStartTimestamp(tab_id, value))
                } else {
                    Ok(value as u64)
                }
            })
            .transpose()?;
        Ok(InitialState {
            next_req_id: U256::from(count_u64),
            start_timestamp,
        })
    }

    async fn query_guarantee(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> Result<Option<GuaranteeRecord>, RequestIdError> {
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "core/tabs/{}/guarantees/{}",
            format!("{tab_id:#x}"),
            format!("{req_id:#x}")
        ));

        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))?;

        if !status.is_success() {
            let message = parse_error_message(&bytes);
            return Err(RequestIdError::fetch(
                tab_id,
                format!("status {status}: {message}"),
            ));
        }

        serde_json::from_slice(&bytes).map_err(|err| RequestIdError::fetch(tab_id, err.to_string()))
    }
}

#[async_trait]
impl RequestIdTracker for LiveRequestIdTracker {
    async fn reserve(
        &self,
        tab_id: U256,
        claimed_req_id: U256,
        claimed_timestamp: u64,
    ) -> Result<RequestIdReservation, RequestIdError> {
        let lock = self.acquire_lock(tab_id).await;

        loop {
            let guard = lock.clone().lock_owned().await;
            if guard.next_req_id.is_none() {
                drop(guard);
                let initial = self.determine_initial(tab_id).await?;
                let mut guard = lock.clone().lock_owned().await;
                if guard.next_req_id.is_none() {
                    guard.next_req_id = Some(initial.next_req_id);
                    guard.start_timestamp = initial.start_timestamp;
                }
                continue;
            }

            let expected = guard.next_req_id.unwrap();

            if let Some(stored) = guard.start_timestamp {
                if claimed_timestamp != stored {
                    return Err(RequestIdError::ModifiedStartTimestamp {
                        tab_id,
                        expected: stored,
                        actual: claimed_timestamp,
                    });
                }
            } else if expected != U256::ZERO {
                return Err(RequestIdError::MissingStartTimestamp(tab_id));
            }

            if claimed_req_id == expected {
                return Ok(RequestIdReservation::new_live(
                    expected,
                    claimed_timestamp,
                    guard,
                ));
            }

            if claimed_req_id < expected {
                if let Some(stored) = guard.start_timestamp {
                    if claimed_timestamp != stored {
                        return Err(RequestIdError::ModifiedStartTimestamp {
                            tab_id,
                            expected: stored,
                            actual: claimed_timestamp,
                        });
                    }
                }
                return Ok(RequestIdReservation::replay(claimed_req_id));
            }

            return Err(RequestIdError::mismatch(tab_id, expected, claimed_req_id));
        }
    }

    async fn fetch_certificate(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> Result<Option<BLSCert>, RequestIdError> {
        let record = self.query_guarantee(tab_id, req_id).await?;
        let Some(record) = record else {
            return Err(RequestIdError::NotFound { tab_id, req_id });
        };

        let Some(cert_str) = record.certificate else {
            return Err(RequestIdError::MissingCertificate { tab_id, req_id });
        };

        let cert = serde_json::from_str::<BLSCert>(&cert_str).map_err(|err| {
            RequestIdError::DecodeCertificate {
                tab_id,
                req_id,
                details: err.to_string(),
            }
        })?;

        Ok(Some(cert))
    }
}

#[derive(Default)]
struct TabState {
    next_req_id: Option<U256>,
    start_timestamp: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestIdError {
    #[error("failed to determine next req_id for tab {tab_id:#x}: {details}")]
    Fetch { tab_id: U256, details: String },
    #[error("guarantee {req_id:#x} for tab {tab_id:#x} not found")]
    NotFound { tab_id: U256, req_id: U256 },
    #[error("guarantee {req_id:#x} for tab {tab_id:#x} missing certificate")]
    MissingCertificate { tab_id: U256, req_id: U256 },
    #[error("failed to decode certificate for tab {tab_id:#x}, req {req_id:#x}: {details}")]
    DecodeCertificate {
        tab_id: U256,
        req_id: U256,
        details: String,
    },
    #[error("tab {tab_id:#x} expected req_id {expected:#x} but received {actual:#x}")]
    Mismatch {
        tab_id: U256,
        expected: U256,
        actual: U256,
    },
    #[error("tab {tab_id:#x} expected start timestamp {expected} but received {actual}")]
    ModifiedStartTimestamp {
        tab_id: U256,
        expected: u64,
        actual: u64,
    },
    #[error("tab {0:#x} is missing a recorded start timestamp")]
    MissingStartTimestamp(U256),
    #[error("tab {0:#x} reported invalid start timestamp {1}")]
    InvalidStartTimestamp(U256, i64),
}

impl RequestIdError {
    fn fetch(tab_id: U256, details: String) -> Self {
        Self::Fetch { tab_id, details }
    }

    fn mismatch(tab_id: U256, expected: U256, actual: U256) -> Self {
        Self::Mismatch {
            tab_id,
            expected,
            actual,
        }
    }
}

pub struct RequestIdReservation {
    expected_req_id: U256,
    claimed_timestamp: u64,
    committed: bool,
    kind: ReservationKind,
}

enum ReservationKind {
    Fresh {
        guard: OwnedMutexGuard<TabState>,
    },
    Replay,
    #[cfg(test)]
    Mock {
        on_commit: Option<Box<dyn FnOnce(U256, u64) + Send + 'static>>,
    },
}

impl RequestIdReservation {
    fn new_live(
        expected_req_id: U256,
        claimed_timestamp: u64,
        guard: OwnedMutexGuard<TabState>,
    ) -> Self {
        Self {
            expected_req_id,
            claimed_timestamp,
            committed: false,
            kind: ReservationKind::Fresh { guard },
        }
    }

    fn replay(expected_req_id: U256) -> Self {
        Self {
            expected_req_id,
            claimed_timestamp: 0,
            committed: true,
            kind: ReservationKind::Replay,
        }
    }

    pub fn is_replay(&self) -> bool {
        matches!(self.kind, ReservationKind::Replay)
    }

    pub fn commit(mut self) {
        if self.committed {
            return;
        }

        match &mut self.kind {
            ReservationKind::Fresh { guard } => {
                let next = self.expected_req_id.saturating_add(U256::from(1u64));
                guard.next_req_id = Some(next);
                if guard.start_timestamp.is_none() {
                    guard.start_timestamp = Some(self.claimed_timestamp);
                }
            }
            ReservationKind::Replay => {}
            #[cfg(test)]
            ReservationKind::Mock { on_commit } => {
                if let Some(cb) = on_commit.take() {
                    cb(self.expected_req_id, self.claimed_timestamp);
                }
            }
        }

        self.committed = true;
    }

    #[cfg(test)]
    pub(crate) fn testing_fresh<F>(
        expected_req_id: U256,
        claimed_timestamp: u64,
        on_commit: F,
    ) -> Self
    where
        F: FnOnce(U256, u64) + Send + 'static,
    {
        Self {
            expected_req_id,
            claimed_timestamp,
            committed: false,
            kind: ReservationKind::Mock {
                on_commit: Some(Box::new(on_commit)),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn testing_replay(expected_req_id: U256) -> Self {
        Self {
            expected_req_id,
            claimed_timestamp: 0,
            committed: true,
            kind: ReservationKind::Replay,
        }
    }
}

#[derive(Deserialize)]
struct GuaranteeRecord {
    #[allow(dead_code)]
    req_id: U256,
    #[serde(rename = "start_timestamp")]
    start_timestamp: i64,
    certificate: Option<String>,
}

struct InitialState {
    next_req_id: U256,
    start_timestamp: Option<u64>,
}
