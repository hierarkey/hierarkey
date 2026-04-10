// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025-2026 Joshua Thijssen <jthijssen@hierarkey.com>

use parking_lot::Mutex;
use std::time::Duration;
use tokio::{sync::watch, task::JoinHandle, time::timeout};
use tracing::{debug, trace};

/// The shutdown allows background tasks to observe when the server is shutting down, so they can stop gracefully.
#[derive(Clone)]
pub struct Shutdown {
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn is_shutdown(&self) -> bool {
        *self.rx.borrow()
    }

    /// Wait until shutdown is requested.
    pub async fn cancelled(&mut self) {
        while !*self.rx.borrow() {
            // changed() returns Err only if sender is dropped;
            // treat that as shutdown as well.
            if self.rx.changed().await.is_err() {
                break;
            }
        }
    }
}

/// The background task manager allows spawning tasks that can observe shutdown signals, and
/// provides a way to request shutdown and wait for tasks to stop gracefully.
pub struct BackgroundTaskManager {
    tx: watch::Sender<bool>,
    tasks: Mutex<Vec<(&'static str, JoinHandle<()>)>>,
}

impl Default for BackgroundTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BackgroundTaskManager {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            tx,
            tasks: Mutex::new(Vec::new()),
        }
    }

    /// Returns a Shutdown structure that can be used to cancel the task manager and all tasks.
    pub fn shutdown_token(&self) -> Shutdown {
        Shutdown {
            rx: self.tx.subscribe(),
        }
    }

    /// Spawn a task that can observe shutdown through a token.
    pub fn spawn<F>(&self, name: &'static str, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        trace!("spawning background task: {}", name);
        let handle = tokio::spawn(fut);
        self.tasks.lock().push((name, handle));
    }

    /// Request shutdown and drain tasks.
    pub async fn shutdown(&self, drain_timeout: Duration) {
        let _ = self.tx.send(true);

        let mut tasks = {
            let mut guard = self.tasks.lock();
            std::mem::take(&mut *guard)
        };

        debug!("Background taskmanager is shutting down");
        debug!(
            "waiting up to {} seconds for tasks to stop gracefully.",
            drain_timeout.as_secs()
        );
        trace!("Current tasks running: ");
        for (name, _) in &tasks {
            trace!(" - {}", name);
        }

        // Drain tasks with timeout, then abort remaining.
        for (name, handle) in tasks.drain(..) {
            match timeout(drain_timeout, handle).await {
                Ok(Ok(())) => {
                    tracing::info!(task = name, "task stopped");
                }
                Ok(Err(join_err)) => {
                    tracing::error!(task = name, error = %join_err, "task join error");
                }
                Err(_) => {
                    tracing::warn!(task = name, "task did not stop in time; aborting");
                }
            }
        }

        trace!("All background tasks have been stopped.");
    }
}
