//! 服务生命周期状态（沿用上游 `state.rs` 的原子状态；IPC server 句柄改在 `server.rs` 内部持有）。

use std::sync::atomic::{AtomicU8, Ordering};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLifecycleState {
    Starting = 0,
    Running = 1,
    RecoveringCore = 2,
    RecoveringIpc = 3,
    Fatal = 4,
}

impl ServiceLifecycleState {
    pub fn from_u8(value: u8) -> ServiceLifecycleState {
        match value {
            1 => ServiceLifecycleState::Running,
            2 => ServiceLifecycleState::RecoveringCore,
            3 => ServiceLifecycleState::RecoveringIpc,
            4 => ServiceLifecycleState::Fatal,
            _ => ServiceLifecycleState::Starting,
        }
    }
}

static SERVICE_STATE: AtomicU8 = AtomicU8::new(ServiceLifecycleState::Starting as u8);

pub fn set_service_lifecycle_state(state: ServiceLifecycleState) {
    SERVICE_STATE.store(state as u8, Ordering::Relaxed);
}

pub fn service_lifecycle_state() -> ServiceLifecycleState {
    ServiceLifecycleState::from_u8(SERVICE_STATE.load(Ordering::Relaxed))
}
