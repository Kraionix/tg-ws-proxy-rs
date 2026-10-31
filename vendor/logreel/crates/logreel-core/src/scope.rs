use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use crate::{Event, Handle, Level};

tokio::task_local! {
    static SCOPE: ScopeData;
}

struct ScopeData {
    handle: Arc<dyn Any + Send + Sync>,
    conn_id: u64,
}

impl ScopeData {
    /// Borrow the handle as the concrete event type, without cloning the Arc.
    fn narrowed<E: Event + Send + 'static>(&self) -> Option<(&Handle<E>, u64)> {
        (&*self.handle as &dyn Any)
            .downcast_ref::<Handle<E>>()
            .map(|handle| (handle, self.conn_id))
    }
}

/// Run a future with a logging scope.
///
/// The scope carries the handle and the connection id; producers inside use
/// the log_event macro and never name the handle. Scopes do not cross a
/// tokio::spawn boundary unless the new task is wrapped again.
pub fn scope<E, F>(
    conn_id: u64,
    handle: Arc<Handle<E>>,
    future: F,
) -> impl Future<Output = F::Output>
where
    E: Event + Send + 'static,
    F: Future,
{
    SCOPE.scope(ScopeData { handle, conn_id }, future)
}

/// Run `f` with the handle and connection id of the innermost scope for
/// this event type, borrowing both.
///
/// This is the path every emitted record takes: it neither clones the
/// [`Arc`] nor re-checks the event type, so it stays as cheap as a task-local
/// lookup. Returns [`None`] outside a scope, or inside a scope created for a
/// different event type.
pub fn with_current<E: Event + Send + 'static, R>(
    f: impl FnOnce(&Handle<E>, u64) -> R,
) -> Option<R> {
    SCOPE
        .try_with(|data| {
            data.narrowed::<E>()
                .map(|(handle, conn_id)| f(handle, conn_id))
        })
        .ok()
        .flatten()
}

/// Handle and connection id of the innermost scope for this event type.
///
/// Clones the [`Arc`] to return it; prefer [`with_current`] where a borrow
/// is enough.
#[must_use]
pub fn current<E: Event + Send + 'static>() -> Option<(Arc<Handle<E>>, u64)> {
    SCOPE
        .try_with(|data| {
            Arc::clone(&data.handle)
                .downcast::<Handle<E>>()
                .ok()
                .map(|handle| (handle, data.conn_id))
        })
        .ok()
        .flatten()
}

/// Emit through the innermost scope; false outside a scope.
pub fn try_emit<E: Event + Send + 'static>(level: Level, category: u8, event: E) -> bool {
    with_current::<E, _>(|handle, conn_id| handle.emit(level, category, conn_id, event))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{current, scope, try_emit, with_current};
    use crate::{DecodeError, Event, Level, Settings, init};
    use logreel_store::SharedSink;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Ping(u64);

    impl Event for Ping {
        const KINDS: u16 = 1;

        fn kind(&self) -> u16 {
            0
        }

        fn encode(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0.to_le_bytes());
        }

        fn decode(_kind: u16, bytes: &[u8]) -> Result<Self, DecodeError> {
            let mut array = [0u8; 8];
            array.copy_from_slice(bytes);
            Ok(Self(u64::from_le_bytes(array)))
        }
    }

    #[test]
    fn scope_carries_handle_and_connection() {
        let sink = SharedSink::new();
        let batches = sink.batches();
        let logger =
            init::<Ping>(Settings::builder().batch_max(1).build(), Box::new(sink)).expect("init");
        let handle = Arc::clone(logger.handle());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(scope(42, handle, async {
            assert!(current::<Ping>().is_some());
            assert!(try_emit(Level::Info, 0, Ping(1)));
        }));
        let _ = logger.shutdown();
        assert_eq!(batches.lock().expect("batches").len(), 1);
    }

    #[test]
    fn with_current_borrows_without_cloning() {
        let sink = SharedSink::new();
        let logger =
            init::<Ping>(Settings::builder().batch_max(1).build(), Box::new(sink)).expect("init");
        let probe = Arc::clone(logger.handle());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(scope(7, Arc::clone(&probe), async move {
            let before = Arc::strong_count(&probe);
            // The callback borrows the handle: the count does not grow while
            // it runs, unlike the cloning current().
            assert_eq!(
                with_current::<Ping, _>(|_, id| (id, Arc::strong_count(&probe))),
                Some((7, before))
            );
        }));
        let _ = logger.shutdown();
    }

    #[test]
    fn nested_scope_wins() {
        let sink = SharedSink::new();
        let logger =
            init::<Ping>(Settings::builder().batch_max(1).build(), Box::new(sink)).expect("init");
        let handle = Arc::clone(logger.handle());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(scope(1, Arc::clone(&handle), async move {
            assert_eq!(with_current::<Ping, _>(|_, id| id), Some(1));
            scope(2, Arc::clone(&handle), async {
                assert_eq!(with_current::<Ping, _>(|_, id| id), Some(2));
            })
            .await;
            assert_eq!(with_current::<Ping, _>(|_, id| id), Some(1));
        }));
        let _ = logger.shutdown();
    }

    #[test]
    fn outside_a_scope_nothing_is_emitted() {
        assert!(!try_emit(Level::Info, 0, Ping(1)));
        assert!(current::<Ping>().is_none());
        assert!(with_current::<Ping, _>(|_, _| ()).is_none());
    }
}
