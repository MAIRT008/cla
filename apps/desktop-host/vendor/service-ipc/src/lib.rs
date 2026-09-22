//! AI Environmental Steward 产品网络服务（由 clash-verge-service-ipc 2.3.3 固定提交复制改名、收窄）。
//!
//! 服务只接受 `core::command::ServiceCommand` 列出的 12 个固定命令；改写类命令必须带宿主签发的授权 envelope。
//! 来源提交与逐文件改动见 UPSTREAM.md。

pub mod core;

#[cfg(feature = "client")]
pub mod client;

pub use crate::core::auth::{canonical_json, sha256_hex, Envelope};
pub use crate::core::command::ServiceCommand;
pub use crate::core::network::{Backends, NetworkService};
pub use crate::core::paths::{
    ServicePaths, CORE_PIPE, KERNEL_VERSION, PRODUCT_APP_ID, PROTOCOL, SERVICE_EXE, SERVICE_NAME, SERVICE_PIPE,
    TEST_SERVICE_PIPE,
};
pub use crate::core::structure::{ServiceError, ServiceReply, ServiceRequest};

#[cfg(feature = "service")]
pub use crate::core::server::{run_product_service, run_service_until_shutdown, ServiceHost};

pub static VERSION: &str = env!("CARGO_PKG_VERSION");
