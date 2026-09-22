//! 服务只暴露的固定命令。上游 `IpcCommand`（/clash/start 接收任意 core_path、/writer 接收任意日志目录、
//! /clash/logs、/magic）全部撤掉；桌面宿主在产品包装层把业务操作映射到下面的语义，WebView 看不到这些枚举。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceCommand {
    Handshake,
    ObserveRuntime,
    ValidateConfig,
    ApplyConfig,
    EnsureProtection,
    ReadProtection,
    CloseManagedConnections,
    StartCore,
    StopCoreForMaintenance,
    RestoreLastValid,
    OpenEmergencyRoute,
    CloseEmergencyRoute,
}

impl ServiceCommand {
    pub const ALL: [ServiceCommand; 12] = [
        ServiceCommand::Handshake,
        ServiceCommand::ObserveRuntime,
        ServiceCommand::ValidateConfig,
        ServiceCommand::ApplyConfig,
        ServiceCommand::EnsureProtection,
        ServiceCommand::ReadProtection,
        ServiceCommand::CloseManagedConnections,
        ServiceCommand::StartCore,
        ServiceCommand::StopCoreForMaintenance,
        ServiceCommand::RestoreLastValid,
        ServiceCommand::OpenEmergencyRoute,
        ServiceCommand::CloseEmergencyRoute,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ServiceCommand::Handshake => "Handshake",
            ServiceCommand::ObserveRuntime => "ObserveRuntime",
            ServiceCommand::ValidateConfig => "ValidateConfig",
            ServiceCommand::ApplyConfig => "ApplyConfig",
            ServiceCommand::EnsureProtection => "EnsureProtection",
            ServiceCommand::ReadProtection => "ReadProtection",
            ServiceCommand::CloseManagedConnections => "CloseManagedConnections",
            ServiceCommand::StartCore => "StartCore",
            ServiceCommand::StopCoreForMaintenance => "StopCoreForMaintenance",
            ServiceCommand::RestoreLastValid => "RestoreLastValid",
            ServiceCommand::OpenEmergencyRoute => "OpenEmergencyRoute",
            ServiceCommand::CloseEmergencyRoute => "CloseEmergencyRoute",
        }
    }

    pub fn route(self) -> &'static str {
        match self {
            ServiceCommand::Handshake => "/v1/handshake",
            ServiceCommand::ObserveRuntime => "/v1/runtime/observe",
            ServiceCommand::ValidateConfig => "/v1/config/validate",
            ServiceCommand::ApplyConfig => "/v1/config/apply",
            ServiceCommand::EnsureProtection => "/v1/protection/ensure",
            ServiceCommand::ReadProtection => "/v1/protection/read",
            ServiceCommand::CloseManagedConnections => "/v1/connections/close",
            ServiceCommand::StartCore => "/v1/core/start",
            ServiceCommand::StopCoreForMaintenance => "/v1/core/stop-for-maintenance",
            ServiceCommand::RestoreLastValid => "/v1/config/restore-last-valid",
            ServiceCommand::OpenEmergencyRoute => "/v1/emergency/open",
            ServiceCommand::CloseEmergencyRoute => "/v1/emergency/close",
        }
    }

    pub fn from_name(name: &str) -> Option<ServiceCommand> {
        ServiceCommand::ALL.iter().copied().find(|command| command.name() == name)
    }

    /// 改写类命令必须带宿主签发的授权 envelope；握手与两类读取不需要，但同样核对产品与协议。
    pub fn requires_envelope(self) -> bool {
        !matches!(self, ServiceCommand::Handshake | ServiceCommand::ObserveRuntime | ServiceCommand::ReadProtection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_table_is_closed_and_routes_are_unique() {
        let mut names: Vec<&str> = ServiceCommand::ALL.iter().map(|command| command.name()).collect();
        let mut routes: Vec<&str> = ServiceCommand::ALL.iter().map(|command| command.route()).collect();
        names.sort();
        names.dedup();
        routes.sort();
        routes.dedup();
        assert_eq!(names.len(), 12);
        assert_eq!(routes.len(), 12);
        for command in ServiceCommand::ALL {
            assert_eq!(ServiceCommand::from_name(command.name()), Some(command));
        }
        for upstream in ["StartClash", "StopClash", "UpdateWriter", "GetClashLogs", "Magic", "Status", "GetVersion"] {
            assert_eq!(ServiceCommand::from_name(upstream), None, "{upstream} 不属于产品命令");
        }
        let reads: Vec<ServiceCommand> = ServiceCommand::ALL.iter().copied().filter(|command| !command.requires_envelope()).collect();
        assert_eq!(reads, vec![ServiceCommand::Handshake, ServiceCommand::ObserveRuntime, ServiceCommand::ReadProtection]);
    }
}
