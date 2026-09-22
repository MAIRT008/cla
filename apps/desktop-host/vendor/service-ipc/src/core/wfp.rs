//! WFP 保护（从桌面宿主移入服务，GUI 进程不调用 WFP）。
//!
//! 设计依据（Microsoft Learn：Filtering Layer Identifiers、Filtering Conditions Available at Each Filtering Layer、
//! Filtering Condition Identifiers、Filter Arbitration、FWPM_FILTER0、FwpmFilterCreateEnumHandle0、FwpmFilterEnum0）：
//! - 层：`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` 授权出站 TCP connect 与首个非 TCP 出站包；该层提供
//!   `FWPM_CONDITION_ALE_APP_ID`（FWP_BYTE_BLOB）、`FWPM_CONDITION_IP_LOCAL_INTERFACE`（FWP_UINT64，本地接口 LUID）、
//!   `FWPM_CONDITION_FLAGS`（FWP_UINT32；`FWP_CONDITION_FLAG_IS_LOOPBACK` 可用于该层）、`FWPM_CONDITION_IP_PROTOCOL`（FWP_UINT8）、
//!   `FWPM_CONDITION_IP_REMOTE_ADDRESS`（IPv4 为 FWP_UINT32 主机字节序，IPv6 为 FWP_BYTE_ARRAY16_TYPE）与
//!   `FWPM_CONDITION_IP_REMOTE_PORT`（FWP_UINT16 主机字节序）。
//! - 基线阻断：每个批准程序每个协议栈一条 `ALE_APP_ID == 程序` 的 BLOCK，权重档 1。过滤器 block 默认是 hard block，
//!   其他子层的 permit 不能覆盖。它从保护请求起一直在，内核异常、配置未知、服务重启都不撤。
//! - 回环端点：只放行模板 `loopback_endpoints` 点名的端点。每个端点一条 PERMIT，条件同时绑定
//!   程序（ALE_APP_ID）、回环标志（FLAGS 含 IS_LOOPBACK，参照 WireGuard for Windows 的 `permitLoopback`）、协议、
//!   单个远端回环地址与单个远端端口，权重档 14，只装在地址所属的协议栈层。清单为空就一条 permit 都没有，回环全拦。
//!   描述里带策略摘要（含模板版本），回读逐条核对。
//! - 残留：安装与回读都按层枚举本产品子层，找出属于该环境、却不在当前策略里的回环 permit
//!   （策略缩减留下的旧端点、上一版本安装的「批准程序全部回环放行」）。安装时删掉；回读时有残留或枚举失败都算未覆盖。
//! - 受管路径：同一产品子层里每个程序每个协议栈再加一条 `ALE_APP_ID == 程序 AND IP_LOCAL_INTERFACE == 本内核 TUN 接口 LUID`
//!   的 PERMIT，权重档 15。子层内按权重从高到低，首个 permit/block 即为本子层结论：经本产品 TUN 发出的连接命中 PERMIT，
//!   经物理网卡或其他隧道发出的未知直连只命中 BLOCK。多个条件字段按 AND 求值。
//! - 故障：TUN 接口随内核进程消失后 permit 的 LUID 不再匹配任何连接；服务在加载配置、停内核、回读失败或实例变化前还会主动删 permit。
//! - 回读：按键取回过滤器，核对层、子层、动作、权重档、条件字段/匹配方式/类型/值、描述标记与程序 app id，键在但语义不符算未覆盖。
//! - 键由「环境 + 程序路径 + v4/v6 + 过滤器种类（端点再加协议/地址/端口）」稳定派生，不同环境互不覆盖；只删本产品拥有的键。

use std::ffi::c_void;
use std::ptr;

use crate::core::network::{loopback_address, LoopbackAddress, LoopbackEndpoint, LoopbackPolicy, ProtectionBackend, ProtectionOutcome};
use crate::core::structure::ServiceError;

const FWP_E_ALREADY_EXISTS: i32 = 0x8032_0009u32 as i32;
const FWP_E_FILTER_NOT_FOUND: i32 = 0x8032_0003u32 as i32;
#[cfg(windows)]
const RPC_C_AUTHN_WINNT: u32 = 10;
const FWP_ACTION_BLOCK: u32 = 0x0000_1001;
const FWP_ACTION_PERMIT: u32 = 0x0000_1002;
const FWP_EMPTY: u32 = 0;
const FWP_UINT8: u32 = 1;
const FWP_UINT16: u32 = 2;
const FWP_UINT32: u32 = 3;
const FWP_UINT64: u32 = 4;
const FWP_BYTE_ARRAY16_TYPE: u32 = 11;
const FWP_BYTE_BLOB_TYPE: u32 = 12;
const FWP_MATCH_EQUAL: u32 = 0;
const FWP_MATCH_FLAGS_ALL_SET: u32 = 6;
const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;
const FWP_FILTER_ENUM_OVERLAPPING: u32 = 1;
const ENUM_ANY_ACTION: u32 = 0xffff_ffff;
const ENUM_PAGE: u32 = 128;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// 枚举失败时写进残留清单的标记：证明不了没有残留，就不能算覆盖。
pub const RESIDUAL_UNVERIFIABLE: &str = "LOOPBACK_ENUMERATION_FAILED";

pub const BLOCK_WEIGHT: u8 = 1;
pub const LOOPBACK_WEIGHT: u8 = 14;
pub const MANAGED_PATH_WEIGHT: u8 = 15;
pub const PRODUCT_SUBLAYER_NAME: &str = "ai-environmental-steward-protect";
const FILTER_NAME: &str = "ai-environmental-steward-protect";

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

const ZERO_GUID: Guid = Guid { data1: 0, data2: 0, data3: 0, data4: [0; 8] };

pub const PRODUCT_SUBLAYER: Guid = Guid {
    data1: 0x8f3a9c2e,
    data2: 0x7b41,
    data3: 0x4d6a,
    data4: [0x9e, 0x15, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6],
};

pub fn layer_ale_auth_connect_v4() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0xc38d57d1, data2: 0x05a7, data3: 0x4c33, data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82] }
    }
}

pub fn layer_ale_auth_connect_v6() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0x4a72393b, data2: 0x319f, data3: 0x44bc, data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4] }
    }
}

pub fn condition_ale_app_id() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_APP_ID)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0xd78e1e87, data2: 0x8644, data3: 0x4ea5, data4: [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71] }
    }
}

pub fn condition_ip_local_interface() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_LOCAL_INTERFACE)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0x4cd62a49, data2: 0x59c3, data3: 0x4969, data4: [0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4] }
    }
}

pub fn condition_flags() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_FLAGS)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0x632ce23b, data2: 0x5167, data3: 0x435c, data4: [0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c] }
    }
}

pub fn condition_ip_protocol() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0x3971ef2b, data2: 0x623e, data3: 0x4f9a, data4: [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7] }
    }
}

pub fn condition_ip_remote_address() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_ADDRESS)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0xb235ae9a, data2: 0x1d64, data3: 0x49b8, data4: [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45] }
    }
}

pub fn condition_ip_remote_port() -> Guid {
    #[cfg(windows)]
    {
        copy_sdk_guid(windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT)
    }
    #[cfg(not(windows))]
    {
        Guid { data1: 0xc35a604d, data2: 0xd22b, data3: 0x4e1a, data4: [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b] }
    }
}

#[cfg(windows)]
fn copy_sdk_guid(value: windows_sys::core::GUID) -> Guid {
    unsafe { std::mem::transmute_copy(&value) }
}

#[repr(C)]
pub struct FwpmDisplayData0 {
    name: *mut u16,
    description: *mut u16,
}

#[repr(C)]
pub struct FwpByteBlob {
    pub size: u32,
    pub data: *mut u8,
}

#[repr(C)]
pub struct FwpmSubLayer0 {
    sub_layer_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    weight: u16,
}

/// FWP_VALUE0 / FWP_CONDITION_VALUE0：类型 + 指针宽度的联合体。UINT8/16/32 存在联合体低位，UINT64、BYTE_ARRAY16 与 BYTE_BLOB 存指针。
#[repr(C)]
struct FwpValue0 {
    data_type: u32,
    value: usize,
}

#[repr(C)]
struct FwpmAction0 {
    action_type: u32,
    filter_type: Guid,
}

#[repr(C)]
pub struct FwpmFilterCondition0 {
    field_key: Guid,
    match_type: u32,
    condition_value: FwpValue0,
}

#[repr(C)]
pub struct FwpmFilter0 {
    filter_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    layer_key: Guid,
    sub_layer_key: Guid,
    weight: FwpValue0,
    num_filter_conditions: u32,
    filter_condition: *mut FwpmFilterCondition0,
    action: FwpmAction0,
    raw_context: u64,
    provider_context_pad: u64,
    reserved: *mut Guid,
    filter_id: u64,
    effective_weight: FwpValue0,
}

/// FWPM_FILTER_ENUM_TEMPLATE0：条件数为 0 时该层全部过滤器都匹配，actionMask 全 1 表示不按动作筛。
#[repr(C)]
pub struct FwpmFilterEnumTemplate0 {
    provider_key: *mut Guid,
    layer_key: Guid,
    enum_type: u32,
    flags: u32,
    provider_context_template: *mut c_void,
    num_filter_conditions: u32,
    filter_condition: *mut FwpmFilterCondition0,
    action_mask: u32,
    callout_key: *mut Guid,
}

pub trait WfpFfi: Send + Sync {
    unsafe fn engine_open(&self, engine: *mut *mut c_void) -> i32;
    unsafe fn sublayer_add(&self, engine: *mut c_void, sublayer: *const FwpmSubLayer0) -> i32;
    unsafe fn get_app_id_from_file_name(&self, file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> i32;
    unsafe fn filter_add(&self, engine: *mut c_void, filter: *const FwpmFilter0, id: *mut u64) -> i32;
    unsafe fn filter_get_by_key(&self, engine: *mut c_void, key: *const Guid, filter: *mut *mut FwpmFilter0) -> i32;
    unsafe fn filter_delete_by_key(&self, engine: *mut c_void, key: *const Guid) -> i32;
    unsafe fn filter_create_enum_handle(&self, engine: *mut c_void, template: *const FwpmFilterEnumTemplate0, handle: *mut *mut c_void) -> i32;
    unsafe fn filter_enum(&self, engine: *mut c_void, handle: *mut c_void, requested: u32, entries: *mut *mut *mut FwpmFilter0, returned: *mut u32) -> i32;
    unsafe fn filter_destroy_enum_handle(&self, engine: *mut c_void, handle: *mut c_void) -> i32;
    unsafe fn sublayer_delete_by_key(&self, engine: *mut c_void, key: *const Guid) -> i32;
    unsafe fn engine_close(&self, engine: *mut c_void) -> i32;
    unsafe fn free_memory(&self, p: *mut *mut c_void);
    unsafe fn interface_alias_to_luid(&self, alias: *const u16, luid: *mut u64) -> u32;
}

pub fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')) || path.starts_with(r"\\")
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterKind {
    Block,
    /// 上一版本安装的「批准程序全部回环放行」。不再安装，只作为迁移清除对象。
    LegacyLoopback,
    LoopbackEndpoint,
    ManagedPath,
}

impl FilterKind {
    fn label(self) -> &'static str {
        match self {
            FilterKind::Block => "block",
            FilterKind::LegacyLoopback => "loopback",
            FilterKind::LoopbackEndpoint => "loopback-endpoint",
            FilterKind::ManagedPath => "managed-path",
        }
    }
}

/// 阻断、受管路径与旧版回环的键派生与上一版本逐字节相同，升级后仍能找到并管理已安装的过滤器。
fn derive_key(environment_ref: &str, process: &str, v6: bool, kind: FilterKind, detail: &str) -> Guid {
    let mut bytes = environment_ref.as_bytes().to_vec();
    bytes.push(b'|');
    bytes.extend_from_slice(process.to_lowercase().as_bytes());
    bytes.extend_from_slice(if v6 { b"|v6" } else { b"|v4" });
    match kind {
        FilterKind::Block => {}
        FilterKind::LegacyLoopback => bytes.extend_from_slice(b"|loopback"),
        FilterKind::LoopbackEndpoint => {
            bytes.extend_from_slice(b"|loopback-endpoint|");
            bytes.extend_from_slice(detail.as_bytes());
        }
        FilterKind::ManagedPath => bytes.extend_from_slice(b"|managed-path"),
    }
    let hash = fnv1a(&bytes);
    let salt = fnv1a(environment_ref.as_bytes());
    Guid {
        data1: hash as u32,
        data2: (salt & 0xffff) as u16,
        data3: if v6 { 0x0006 } else { 0x0004 },
        data4: [
            0xa1,
            0x57,
            (salt >> 16) as u8,
            (hash >> 32) as u8,
            (hash >> 40) as u8,
            (hash >> 48) as u8,
            (hash >> 56) as u8,
            match kind {
                FilterKind::Block => 0x01,
                FilterKind::ManagedPath => 0x02,
                FilterKind::LegacyLoopback => 0x03,
                FilterKind::LoopbackEndpoint => 0x04,
            },
        ],
    }
}

/// 本产品拥有的阻断过滤器键：环境、程序路径（大小写不敏感）与 v4/v6 共同决定。
pub fn stable_filter_key(environment_ref: &str, process: &str, v6: bool) -> Guid {
    derive_key(environment_ref, process, v6, FilterKind::Block, "")
}

pub fn managed_path_filter_key(environment_ref: &str, process: &str, v6: bool) -> Guid {
    derive_key(environment_ref, process, v6, FilterKind::ManagedPath, "")
}

pub fn legacy_loopback_filter_key(environment_ref: &str, process: &str, v6: bool) -> Guid {
    derive_key(environment_ref, process, v6, FilterKind::LegacyLoopback, "")
}

/// 端点 permit 的键：程序 + 协议 + 地址 + 端口；协议栈由地址决定。
pub fn loopback_endpoint_filter_key(environment_ref: &str, process: &str, endpoint: &LoopbackEndpoint) -> Guid {
    let v6 = matches!(loopback_address(&endpoint.address), Some(LoopbackAddress::V6(_)));
    let detail = format!("{}|{}|{}", endpoint.transport, endpoint.address, endpoint.port);
    derive_key(environment_ref, process, v6, FilterKind::LoopbackEndpoint, &detail)
}

/// 写进过滤器描述、回读时核对的环境标记（阻断、受管路径、旧版回环）。
pub fn filter_marker(environment_ref: &str, v6: bool, kind: FilterKind) -> String {
    format!("steward|{}|{}|{}", kind.label(), if v6 { "v6" } else { "v4" }, environment_ref)
}

/// 端点 permit 的标记另带策略摘要，模板版本或清单变了，旧 permit 回读就对不上。
pub fn loopback_endpoint_marker(environment_ref: &str, v6: bool, digest: &str) -> String {
    format!("steward|loopback-endpoint|{}|{}|{}", if v6 { "v6" } else { "v4" }, digest, environment_ref)
}

/// 描述是否标明「本环境的回环 permit」：旧版全回环放行，或任意策略摘要下的端点 permit。
fn owned_loopback_marker(description: &str, environment_ref: &str) -> bool {
    for v6 in [false, true] {
        if description == filter_marker(environment_ref, v6, FilterKind::LegacyLoopback) {
            return true;
        }
        let prefix = format!("steward|loopback-endpoint|{}|", if v6 { "v6" } else { "v4" });
        if let Some(rest) = description.strip_prefix(prefix.as_str()) {
            let bytes = rest.as_bytes();
            if bytes.len() > 65 && bytes[..64].iter().all(u8::is_ascii_hexdigit) && bytes[64] == b'|' && &rest[65..] == environment_ref {
                return true;
            }
        }
    }
    false
}

fn guid_text(guid: &Guid) -> String {
    let tail: String = guid.data4.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{:08x}-{:04x}-{:04x}-{}-{}", guid.data1, guid.data2, guid.data3, &tail[..4], &tail[4..])
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn read_wide(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut units = Vec::new();
    for offset in 0..4096 {
        let unit = *pointer.add(offset);
        if unit == 0 {
            return Some(String::from_utf16_lossy(&units));
        }
        units.push(unit);
    }
    None
}

/// 程序条件之外的条件。每个值对应唯一的条件字段、匹配方式与数据类型。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    Interface(u64),
    LoopbackFlag,
    Protocol(u8),
    RemoteV4(u32),
    RemoteV6([u8; 16]),
    RemotePort(u16),
}

/// 本产品对一条过滤器的完整定义；添加与回读都用它。
pub struct ExpectedFilter {
    pub key: Guid,
    pub layer: Guid,
    pub action: u32,
    pub weight: u8,
    pub app_id: Vec<u8>,
    pub conditions: Vec<Condition>,
    pub marker: String,
}

fn layer_for(v6: bool) -> Guid {
    if v6 {
        layer_ale_auth_connect_v6()
    } else {
        layer_ale_auth_connect_v4()
    }
}

impl ExpectedFilter {
    fn block(environment_ref: &str, process: &str, v6: bool, app_id: Vec<u8>) -> ExpectedFilter {
        ExpectedFilter {
            key: stable_filter_key(environment_ref, process, v6),
            layer: layer_for(v6),
            action: FWP_ACTION_BLOCK,
            weight: BLOCK_WEIGHT,
            app_id,
            conditions: Vec::new(),
            marker: filter_marker(environment_ref, v6, FilterKind::Block),
        }
    }

    fn managed_path(environment_ref: &str, process: &str, v6: bool, app_id: Vec<u8>, interface_luid: u64) -> ExpectedFilter {
        ExpectedFilter {
            key: managed_path_filter_key(environment_ref, process, v6),
            layer: layer_for(v6),
            action: FWP_ACTION_PERMIT,
            weight: MANAGED_PATH_WEIGHT,
            app_id,
            conditions: vec![Condition::Interface(interface_luid)],
            marker: filter_marker(environment_ref, v6, FilterKind::ManagedPath),
        }
    }

    /// 地址或协议不合法时不生成 permit：这一项按回环全拦处理。
    fn loopback_endpoint(environment_ref: &str, process: &str, endpoint: &LoopbackEndpoint, digest: &str, app_id: Vec<u8>) -> Option<ExpectedFilter> {
        let protocol = match endpoint.transport.as_str() {
            "tcp" => IPPROTO_TCP,
            "udp" => IPPROTO_UDP,
            _ => return None,
        };
        let (v6, remote) = match loopback_address(&endpoint.address)? {
            LoopbackAddress::V4(address) => (false, Condition::RemoteV4(address)),
            LoopbackAddress::V6(address) => (true, Condition::RemoteV6(address)),
        };
        if endpoint.port == 0 {
            return None;
        }
        Some(ExpectedFilter {
            key: loopback_endpoint_filter_key(environment_ref, process, endpoint),
            layer: layer_for(v6),
            action: FWP_ACTION_PERMIT,
            weight: LOOPBACK_WEIGHT,
            app_id,
            conditions: vec![Condition::LoopbackFlag, Condition::Protocol(protocol), remote, Condition::RemotePort(endpoint.port)],
            marker: loopback_endpoint_marker(environment_ref, v6, digest),
        })
    }
}

/// 一次安装或回读要核对的过滤器集合。
pub enum FilterPlan<'a> {
    /// 阻断 + 当前策略点名的回环端点 permit。
    Baseline(&'a LoopbackPolicy),
    ManagedPath(u64),
}

impl FilterPlan<'_> {
    fn filters(&self, environment_ref: &str, process: &str, app_id: &[u8]) -> Vec<ExpectedFilter> {
        match self {
            FilterPlan::Baseline(policy) => {
                let mut filters = vec![
                    ExpectedFilter::block(environment_ref, process, false, app_id.to_vec()),
                    ExpectedFilter::block(environment_ref, process, true, app_id.to_vec()),
                ];
                for endpoint in policy.endpoints.iter().filter(|endpoint| endpoint.source_process_path.eq_ignore_ascii_case(process)) {
                    if let Some(filter) = ExpectedFilter::loopback_endpoint(environment_ref, process, endpoint, &policy.digest, app_id.to_vec()) {
                        filters.push(filter);
                    }
                }
                filters
            }
            FilterPlan::ManagedPath(luid) => vec![
                ExpectedFilter::managed_path(environment_ref, process, false, app_id.to_vec(), *luid),
                ExpectedFilter::managed_path(environment_ref, process, true, app_id.to_vec(), *luid),
            ],
        }
    }

    /// 不依赖 app id 的键：取不到 app id 时用来判断是「缺」还是「在但对不上」。
    fn keys(&self, environment_ref: &str, process: &str) -> Vec<Guid> {
        match self {
            FilterPlan::Baseline(policy) => {
                let mut keys = vec![stable_filter_key(environment_ref, process, false), stable_filter_key(environment_ref, process, true)];
                keys.extend(endpoint_keys(environment_ref, &[process.to_string()], policy));
                keys
            }
            FilterPlan::ManagedPath(_) => vec![managed_path_filter_key(environment_ref, process, false), managed_path_filter_key(environment_ref, process, true)],
        }
    }
}

/// 当前策略应当存在的端点 permit 键；不在这里的本环境回环 permit 都是残留。
fn endpoint_keys(environment_ref: &str, processes: &[String], policy: &LoopbackPolicy) -> Vec<Guid> {
    let mut keys = Vec::new();
    for process in processes {
        for endpoint in policy.endpoints.iter().filter(|endpoint| endpoint.source_process_path.eq_ignore_ascii_case(process)) {
            if loopback_address(&endpoint.address).is_some() {
                keys.push(loopback_endpoint_filter_key(environment_ref, process, endpoint));
            }
        }
    }
    keys
}

/// 权重回读：BFE 可能原样返回 FWP_UINT8 档位，也可能返回算好的 FWP_UINT64（高 4 位是档位）。
unsafe fn weight_matches(weight: &FwpValue0, expected: u8) -> bool {
    match weight.data_type {
        FWP_UINT8 => (weight.value & 0xff) as u8 == expected,
        FWP_UINT64 if weight.value != 0 => (*(weight.value as *const u64) >> 60) as u8 == expected,
        _ => false,
    }
}

/// 把回读到的一个非程序条件还原成本产品认识的条件；字段、匹配方式或类型任何一项不认识都返回 None。
unsafe fn decode_condition(condition: &FwpmFilterCondition0) -> Option<Condition> {
    let value = &condition.condition_value;
    let field = condition.field_key;
    if field == condition_ip_local_interface() && condition.match_type == FWP_MATCH_EQUAL && value.data_type == FWP_UINT64 && value.value != 0 {
        return Some(Condition::Interface(*(value.value as *const u64)));
    }
    if field == condition_flags() && condition.match_type == FWP_MATCH_FLAGS_ALL_SET && value.data_type == FWP_UINT32 {
        return ((value.value & 0xffff_ffff) as u32 == FWP_CONDITION_FLAG_IS_LOOPBACK).then_some(Condition::LoopbackFlag);
    }
    if field == condition_ip_protocol() && condition.match_type == FWP_MATCH_EQUAL && value.data_type == FWP_UINT8 {
        return Some(Condition::Protocol((value.value & 0xff) as u8));
    }
    if field == condition_ip_remote_address() && condition.match_type == FWP_MATCH_EQUAL {
        if value.data_type == FWP_UINT32 {
            return Some(Condition::RemoteV4((value.value & 0xffff_ffff) as u32));
        }
        if value.data_type == FWP_BYTE_ARRAY16_TYPE && value.value != 0 {
            return Some(Condition::RemoteV6(*(value.value as *const [u8; 16])));
        }
    }
    if field == condition_ip_remote_port() && condition.match_type == FWP_MATCH_EQUAL && value.data_type == FWP_UINT16 {
        return Some(Condition::RemotePort((value.value & 0xffff) as u16));
    }
    None
}

/// 回读过滤器是否与本产品定义逐项一致：层、子层、动作、权重档、描述标记、程序与其余条件的完整集合。
unsafe fn filter_matches(filter: *const FwpmFilter0, expected: &ExpectedFilter) -> bool {
    if filter.is_null() {
        return false;
    }
    let filter = &*filter;
    if filter.filter_key != expected.key
        || filter.layer_key != expected.layer
        || filter.sub_layer_key != PRODUCT_SUBLAYER
        || filter.action.action_type != expected.action
        || !weight_matches(&filter.weight, expected.weight)
    {
        return false;
    }
    if read_wide(filter.display_data.description).as_deref() != Some(expected.marker.as_str()) {
        return false;
    }
    let wanted = expected.conditions.len() + 1;
    if filter.num_filter_conditions as usize != wanted || filter.filter_condition.is_null() {
        return false;
    }
    let mut app_ok = false;
    let mut seen: Vec<Condition> = Vec::new();
    for condition in std::slice::from_raw_parts(filter.filter_condition, wanted) {
        let value = &condition.condition_value;
        if condition.field_key == condition_ale_app_id() {
            if app_ok || condition.match_type != FWP_MATCH_EQUAL || value.data_type != FWP_BYTE_BLOB_TYPE || value.value == 0 {
                return false;
            }
            let blob = &*(value.value as *const FwpByteBlob);
            if blob.data.is_null() || std::slice::from_raw_parts(blob.data, blob.size as usize) != expected.app_id.as_slice() {
                return false;
            }
            app_ok = true;
            continue;
        }
        match decode_condition(condition) {
            Some(decoded) if expected.conditions.contains(&decoded) && !seen.contains(&decoded) => seen.push(decoded),
            _ => return false,
        }
    }
    app_ok && seen.len() == expected.conditions.len()
}

enum Installed {
    Created,
    Present,
    Replaced,
}

/// 枚举取出的一条过滤器：只留判断归属与删除顺序要用的字段。
struct ListedFilter {
    key: Guid,
    sub_layer_key: Guid,
    action: u32,
    description: Option<String>,
}

/// 卸载时对本产品子层的清扫：`found` 是清扫前枚举到的过滤器数，`remaining` 是清扫后再次枚举到的数量。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProductSweep {
    pub found: usize,
    pub removed: usize,
    pub remaining: usize,
    pub code: Option<String>,
    pub native_status: Option<i64>,
}

impl ProductSweep {
    /// 枚举与删除都没有报错、复核为零，才算子层里没有本产品过滤器。
    pub fn clean(&self) -> bool {
        self.code.is_none() && self.remaining == 0
    }
}

pub struct WfpProtection<F: WfpFfi> {
    ffi: F,
}

impl<F: WfpFfi> WfpProtection<F> {
    pub fn new(ffi: F) -> WfpProtection<F> {
        WfpProtection { ffi }
    }

    fn failure(code: &str, status: i32, processes: &[String]) -> ProtectionOutcome {
        ProtectionOutcome {
            missing: processes.to_vec(),
            code: Some(code.to_string()),
            native_status: Some(i64::from(status)),
            ..ProtectionOutcome::default()
        }
    }

    unsafe fn app_id(&self, path: &str) -> Result<Vec<u8>, i32> {
        let wide_path = wide(path);
        let mut blob: *mut FwpByteBlob = ptr::null_mut();
        let status = self.ffi.get_app_id_from_file_name(wide_path.as_ptr(), &mut blob);
        if status != 0 || blob.is_null() {
            return Err(if status == 0 { -1 } else { status });
        }
        let bytes = if (*blob).data.is_null() { Vec::new() } else { std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec() };
        let mut memory = blob as *mut c_void;
        self.ffi.free_memory(&mut memory);
        if bytes.is_empty() {
            return Err(-1);
        }
        Ok(bytes)
    }

    unsafe fn ensure_sublayer(&self, engine: *mut c_void) -> Result<bool, i32> {
        let mut name = wide(PRODUCT_SUBLAYER_NAME);
        let mut description = wide("AI Environmental Steward protected-program block, loopback endpoint and managed-path permits");
        let sublayer = FwpmSubLayer0 {
            sub_layer_key: PRODUCT_SUBLAYER,
            display_data: FwpmDisplayData0 { name: name.as_mut_ptr(), description: description.as_mut_ptr() },
            flags: 0,
            provider_key: ptr::null_mut(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null_mut() },
            weight: 0xffff,
        };
        match self.ffi.sublayer_add(engine, &sublayer) {
            0 => Ok(true),
            FWP_E_ALREADY_EXISTS => Ok(false),
            status => Err(status),
        }
    }

    unsafe fn add_filter(&self, engine: *mut c_void, expected: &ExpectedFilter) -> i32 {
        let mut app_id = expected.app_id.clone();
        let mut blob = FwpByteBlob { size: app_id.len() as u32, data: app_id.as_mut_ptr() };
        let mut luid = expected.conditions.iter().find_map(|item| if let Condition::Interface(value) = item { Some(*value) } else { None }).unwrap_or(0);
        let mut remote_v6 = expected.conditions.iter().find_map(|item| if let Condition::RemoteV6(value) = item { Some(*value) } else { None }).unwrap_or([0u8; 16]);
        let mut conditions = vec![FwpmFilterCondition0 {
            field_key: condition_ale_app_id(),
            match_type: FWP_MATCH_EQUAL,
            condition_value: FwpValue0 { data_type: FWP_BYTE_BLOB_TYPE, value: &mut blob as *mut FwpByteBlob as usize },
        }];
        for condition in &expected.conditions {
            let (field_key, match_type, data_type, value) = match *condition {
                Condition::Interface(_) => (condition_ip_local_interface(), FWP_MATCH_EQUAL, FWP_UINT64, &mut luid as *mut u64 as usize),
                Condition::LoopbackFlag => (condition_flags(), FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_CONDITION_FLAG_IS_LOOPBACK as usize),
                Condition::Protocol(protocol) => (condition_ip_protocol(), FWP_MATCH_EQUAL, FWP_UINT8, usize::from(protocol)),
                Condition::RemoteV4(address) => (condition_ip_remote_address(), FWP_MATCH_EQUAL, FWP_UINT32, address as usize),
                Condition::RemoteV6(_) => (condition_ip_remote_address(), FWP_MATCH_EQUAL, FWP_BYTE_ARRAY16_TYPE, &mut remote_v6 as *mut [u8; 16] as usize),
                Condition::RemotePort(port) => (condition_ip_remote_port(), FWP_MATCH_EQUAL, FWP_UINT16, usize::from(port)),
            };
            conditions.push(FwpmFilterCondition0 { field_key, match_type, condition_value: FwpValue0 { data_type, value } });
        }
        let mut name = wide(FILTER_NAME);
        let mut description = wide(&expected.marker);
        let filter = FwpmFilter0 {
            filter_key: expected.key,
            display_data: FwpmDisplayData0 { name: name.as_mut_ptr(), description: description.as_mut_ptr() },
            flags: 0,
            provider_key: ptr::null_mut(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null_mut() },
            layer_key: expected.layer,
            sub_layer_key: PRODUCT_SUBLAYER,
            weight: FwpValue0 { data_type: FWP_UINT8, value: usize::from(expected.weight) },
            num_filter_conditions: conditions.len() as u32,
            filter_condition: conditions.as_mut_ptr(),
            action: FwpmAction0 { action_type: expected.action, filter_type: ZERO_GUID },
            raw_context: 0,
            provider_context_pad: 0,
            reserved: ptr::null_mut(),
            filter_id: 0,
            effective_weight: FwpValue0 { data_type: FWP_EMPTY, value: 0 },
        };
        let mut filter_id = 0u64;
        self.ffi.filter_add(engine, &filter, &mut filter_id)
    }

    /// 回读语义：Ok(None) 表示键不存在，Ok(Some(false)) 表示键在但语义不符；Err 是读取本身出错，不能当成不存在。
    unsafe fn read_filter(&self, engine: *mut c_void, expected: &ExpectedFilter) -> Result<Option<bool>, i32> {
        let mut filter: *mut FwpmFilter0 = ptr::null_mut();
        match self.ffi.filter_get_by_key(engine, &expected.key, &mut filter) {
            0 if !filter.is_null() => {}
            0 => return Err(-1),
            FWP_E_FILTER_NOT_FOUND => return Ok(None),
            status => return Err(status),
        }
        let matches = filter_matches(filter, expected);
        let mut memory = filter as *mut c_void;
        self.ffi.free_memory(&mut memory);
        Ok(Some(matches))
    }

    unsafe fn key_present(&self, engine: *mut c_void, key: &Guid) -> Result<bool, i32> {
        let mut filter: *mut FwpmFilter0 = ptr::null_mut();
        match self.ffi.filter_get_by_key(engine, key, &mut filter) {
            0 if !filter.is_null() => {}
            0 => return Err(-1),
            FWP_E_FILTER_NOT_FOUND => return Ok(false),
            status => return Err(status),
        }
        let mut memory = filter as *mut c_void;
        self.ffi.free_memory(&mut memory);
        Ok(true)
    }

    /// 已有同键过滤器但语义不符时删掉重建（例如接口 LUID 或策略摘要变了）；语义一致就保留。
    unsafe fn install(&self, engine: *mut c_void, expected: &ExpectedFilter) -> Result<Installed, i32> {
        match self.ffi_add_or_exists(engine, expected) {
            Ok(true) => Ok(Installed::Created),
            Ok(false) => {
                if self.read_filter(engine, expected) == Ok(Some(true)) {
                    return Ok(Installed::Present);
                }
                let deleted = self.ffi.filter_delete_by_key(engine, &expected.key);
                if deleted != 0 && deleted != FWP_E_FILTER_NOT_FOUND {
                    return Err(deleted);
                }
                match self.add_filter(engine, expected) {
                    0 => Ok(Installed::Replaced),
                    status => Err(status),
                }
            }
            Err(status) => Err(status),
        }
    }

    unsafe fn ffi_add_or_exists(&self, engine: *mut c_void, expected: &ExpectedFilter) -> Result<bool, i32> {
        match self.add_filter(engine, expected) {
            0 => Ok(true),
            FWP_E_ALREADY_EXISTS => Ok(false),
            status => Err(status),
        }
    }

    unsafe fn delete_keys(&self, engine: *mut c_void, keys: &[Guid], outcome: &mut ProtectionOutcome) {
        for key in keys {
            let status = self.ffi.filter_delete_by_key(engine, key);
            if status == 0 {
                outcome.removed += 1;
            } else if status != FWP_E_FILTER_NOT_FOUND {
                outcome.code = Some("NATIVE_FILTER_DELETE_FAILED".to_string());
                outcome.native_status = Some(i64::from(status));
            }
        }
    }

    /// 逐页枚举，取出每条过滤器的键、子层、动作与描述；任何一页失败都如实返回状态，不当成「没有」。
    /// `template` 为空指针时枚举全部层（FwpmFilterCreateEnumHandle0 的模板参数可选）。
    unsafe fn list_filters(&self, engine: *mut c_void, template: *const FwpmFilterEnumTemplate0) -> Result<Vec<ListedFilter>, i32> {
        let mut listed = Vec::new();
        let mut handle: *mut c_void = ptr::null_mut();
        let created = self.ffi.filter_create_enum_handle(engine, template, &mut handle);
        if created != 0 {
            return Err(created);
        }
        loop {
            let mut entries: *mut *mut FwpmFilter0 = ptr::null_mut();
            let mut returned = 0u32;
            let status = self.ffi.filter_enum(engine, handle, ENUM_PAGE, &mut entries, &mut returned);
            if status != 0 {
                self.ffi.filter_destroy_enum_handle(engine, handle);
                return Err(status);
            }
            if entries.is_null() {
                break;
            }
            for entry in std::slice::from_raw_parts(entries, returned as usize) {
                if entry.is_null() {
                    continue;
                }
                let filter = &**entry;
                listed.push(ListedFilter {
                    key: filter.filter_key,
                    sub_layer_key: filter.sub_layer_key,
                    action: filter.action.action_type,
                    description: read_wide(filter.display_data.description),
                });
            }
            let mut memory = entries as *mut c_void;
            self.ffi.free_memory(&mut memory);
            if returned < ENUM_PAGE {
                break;
            }
        }
        self.ffi.filter_destroy_enum_handle(engine, handle);
        Ok(listed)
    }

    /// 按层枚举本产品子层，返回属于该环境的回环 permit 键（旧版全回环放行与任意摘要下的端点 permit）。
    unsafe fn owned_loopback_keys(&self, engine: *mut c_void, environment_ref: &str) -> Result<Vec<Guid>, i32> {
        let mut keys = Vec::new();
        for layer in [layer_ale_auth_connect_v4(), layer_ale_auth_connect_v6()] {
            let template = FwpmFilterEnumTemplate0 {
                provider_key: ptr::null_mut(),
                layer_key: layer,
                enum_type: FWP_FILTER_ENUM_OVERLAPPING,
                flags: 0,
                provider_context_template: ptr::null_mut(),
                num_filter_conditions: 0,
                filter_condition: ptr::null_mut(),
                action_mask: ENUM_ANY_ACTION,
                callout_key: ptr::null_mut(),
            };
            for filter in self.list_filters(engine, &template)? {
                let owned = filter.sub_layer_key == PRODUCT_SUBLAYER
                    && filter.description.as_deref().map(|text| owned_loopback_marker(text, environment_ref)).unwrap_or(false);
                if owned && !keys.contains(&filter.key) {
                    keys.push(filter.key);
                }
            }
        }
        Ok(keys)
    }

    /// 本产品子层里的全部过滤器（不分层、不分环境、不分种类）：键与动作。
    unsafe fn product_filters(&self, engine: *mut c_void) -> Result<Vec<(Guid, u32)>, i32> {
        let mut found: Vec<(Guid, u32)> = Vec::new();
        for filter in self.list_filters(engine, ptr::null())? {
            if filter.sub_layer_key == PRODUCT_SUBLAYER && !found.iter().any(|(key, _)| *key == filter.key) {
                found.push((filter.key, filter.action));
            }
        }
        Ok(found)
    }

    /// 卸载用的子层清扫：不看运行状态记录，直接枚举本产品子层的全部过滤器。`release` 为真时先删 permit；
    /// permit 删除没有报错、重新枚举也只剩阻断，才删阻断，删完重新枚举；为假时只枚举。打开引擎、枚举或删除任何一步失败都写错误码，不算撤净。
    /// permit 没删净时一条阻断都不删：卸载随后失败、服务重启，而运行状态可能已经丢了，删掉的阻断没人能补回。
    pub fn sweep_product_sublayer(&self, release: bool) -> ProductSweep {
        unsafe {
            let mut engine = ptr::null_mut();
            let open = self.ffi.engine_open(&mut engine);
            if open != 0 {
                return ProductSweep { code: Some("NATIVE_ENGINE_OPEN_FAILED".to_string()), native_status: Some(i64::from(open)), ..ProductSweep::default() };
            }
            let mut sweep = ProductSweep::default();
            match self.product_filters(engine) {
                Err(status) => {
                    sweep.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                    sweep.native_status = Some(i64::from(status));
                }
                Ok(found) => {
                    sweep.found = found.len();
                    sweep.remaining = found.len();
                    if release {
                        let permits: Vec<Guid> = found.iter().filter(|(_, action)| *action != FWP_ACTION_BLOCK).map(|(key, _)| *key).collect();
                        let mut deleted = ProtectionOutcome::default();
                        self.delete_keys(engine, &permits, &mut deleted);
                        if deleted.code.is_none() {
                            match self.product_filters(engine) {
                                Ok(left) if left.iter().all(|(_, action)| *action == FWP_ACTION_BLOCK) => {
                                    let blocks: Vec<Guid> = left.into_iter().map(|(key, _)| key).collect();
                                    self.delete_keys(engine, &blocks, &mut deleted);
                                }
                                Ok(_) => deleted.code = Some("PERMIT_NOT_RELEASED".to_string()),
                                Err(status) => {
                                    deleted.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                                    deleted.native_status = Some(i64::from(status));
                                }
                            }
                        }
                        sweep.removed = deleted.removed;
                        sweep.code = deleted.code;
                        sweep.native_status = deleted.native_status;
                        match self.product_filters(engine) {
                            Ok(left) => sweep.remaining = left.len(),
                            Err(status) => {
                                sweep.remaining = sweep.found.saturating_sub(sweep.removed);
                                sweep.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                                sweep.native_status = Some(i64::from(status));
                            }
                        }
                    }
                }
            }
            self.ffi.engine_close(engine);
            sweep
        }
    }

    fn install_filters(&self, environment_ref: &str, processes: &[String], plan: &FilterPlan) -> ProtectionOutcome {
        let managed_path = matches!(plan, FilterPlan::ManagedPath(_));
        if processes.is_empty() || processes.iter().any(|path| !is_absolute_windows_path(path)) {
            return WfpProtection::<F>::failure("PROCESS_SCOPE_INVALID", 0, processes);
        }
        unsafe {
            let mut engine = ptr::null_mut();
            let open = self.ffi.engine_open(&mut engine);
            if open != 0 {
                return WfpProtection::<F>::failure("NATIVE_ENGINE_OPEN_FAILED", open, processes);
            }
            let created_sublayer = match self.ensure_sublayer(engine) {
                Ok(created) => created,
                Err(status) => {
                    self.ffi.engine_close(engine);
                    return WfpProtection::<F>::failure("NATIVE_SUBLAYER_ADD_FAILED", status, processes);
                }
            };
            // 先删不属于当前策略的回环 permit（缩减留下的旧端点、历史全回环放行）；删不掉也继续装阻断，回读会把残留报出来。
            let mut sweep = ProtectionOutcome::default();
            if let FilterPlan::Baseline(policy) = plan {
                let wanted = endpoint_keys(environment_ref, processes, policy);
                match self.owned_loopback_keys(engine, environment_ref) {
                    Ok(owned) => {
                        let stale: Vec<Guid> = owned.into_iter().filter(|key| !wanted.contains(key)).collect();
                        self.delete_keys(engine, &stale, &mut sweep);
                    }
                    Err(status) => {
                        sweep.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                        sweep.native_status = Some(i64::from(status));
                    }
                }
            }
            let mut created: Vec<Guid> = Vec::new();
            let mut touched: Vec<Guid> = Vec::new();
            let mut failure: Option<(&str, i32)> = None;
            'programs: for path in processes {
                let app_id = match self.app_id(path) {
                    Ok(app_id) => app_id,
                    Err(status) => {
                        failure = Some(("NATIVE_APP_ID_FAILED", status));
                        break 'programs;
                    }
                };
                for expected in plan.filters(environment_ref, path, &app_id) {
                    match self.install(engine, &expected) {
                        Ok(Installed::Created) => {
                            created.push(expected.key);
                            touched.push(expected.key);
                        }
                        Ok(Installed::Replaced) => touched.push(expected.key),
                        Ok(Installed::Present) => {}
                        Err(status) => {
                            failure = Some(("NATIVE_FILTER_ADD_FAILED", status));
                            break 'programs;
                        }
                    }
                }
            }
            if let Some((code, status)) = failure {
                // 基线只回滚本次新建的键，先前有效的保护不动；受管路径失败时本次动过的 permit 全部删掉，保持关闭。
                let rollback = if managed_path { &touched } else { &created };
                for key in rollback.iter().rev() {
                    self.ffi.filter_delete_by_key(engine, key);
                }
                if !managed_path && created_sublayer {
                    self.ffi.sublayer_delete_by_key(engine, &PRODUCT_SUBLAYER);
                }
                self.ffi.engine_close(engine);
                let mut outcome = WfpProtection::<F>::failure(code, status, processes);
                outcome.rolled_back = true;
                outcome.removed = sweep.removed;
                return outcome;
            }
            self.ffi.engine_close(engine);
            ProtectionOutcome { created: created.len(), removed: sweep.removed, code: sweep.code, native_status: sweep.native_status, ..ProtectionOutcome::default() }
        }
    }

    fn read_filters(&self, environment_ref: &str, processes: &[String], plan: &FilterPlan) -> ProtectionOutcome {
        unsafe {
            let mut engine = ptr::null_mut();
            let open = self.ffi.engine_open(&mut engine);
            if open != 0 {
                let mut outcome = WfpProtection::<F>::failure("NATIVE_ENGINE_OPEN_FAILED", open, processes);
                if matches!(plan, FilterPlan::Baseline(_)) {
                    outcome.residual.push(RESIDUAL_UNVERIFIABLE.to_string());
                }
                return outcome;
            }
            let mut outcome = ProtectionOutcome::default();
            // 单键读取出错时这个程序算「在但对不上」：既不算覆盖，也不能当成已撤净。
            let mut read_failed: Option<i32> = None;
            for path in processes {
                let app_id = match self.app_id(path) {
                    Ok(app_id) => app_id,
                    Err(_) => {
                        let mut any_key = false;
                        for key in plan.keys(environment_ref, path) {
                            match self.key_present(engine, &key) {
                                Ok(present) => any_key = any_key || present,
                                Err(status) => {
                                    any_key = true;
                                    read_failed = Some(status);
                                }
                            }
                        }
                        if any_key {
                            outcome.mismatched.push(path.clone());
                        } else {
                            outcome.missing.push(path.clone());
                        }
                        continue;
                    }
                };
                let mut all = true;
                let mut any_present = false;
                for expected in plan.filters(environment_ref, path, &app_id) {
                    match self.read_filter(engine, &expected) {
                        Ok(Some(true)) => any_present = true,
                        Ok(Some(false)) => {
                            any_present = true;
                            all = false;
                        }
                        Ok(None) => all = false,
                        Err(status) => {
                            any_present = true;
                            all = false;
                            read_failed = Some(status);
                        }
                    }
                }
                if all {
                    outcome.installed.push(path.clone());
                } else if any_present {
                    outcome.mismatched.push(path.clone());
                } else {
                    outcome.missing.push(path.clone());
                }
            }
            if let Some(status) = read_failed {
                outcome.code = Some("NATIVE_FILTER_READ_FAILED".to_string());
                outcome.native_status = Some(i64::from(status));
            }
            if let FilterPlan::Baseline(policy) = plan {
                let wanted = endpoint_keys(environment_ref, processes, policy);
                match self.owned_loopback_keys(engine, environment_ref) {
                    Ok(owned) => outcome.residual = owned.iter().filter(|key| !wanted.contains(*key)).map(guid_text).collect(),
                    Err(status) => {
                        outcome.residual.push(RESIDUAL_UNVERIFIABLE.to_string());
                        outcome.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                        outcome.native_status = Some(i64::from(status));
                    }
                }
            }
            self.ffi.engine_close(engine);
            outcome
        }
    }

    fn delete_derived(&self, environment_ref: &str, processes: &[String], kinds: &[FilterKind], sweep_loopback: bool) -> ProtectionOutcome {
        unsafe {
            let mut engine = ptr::null_mut();
            let open = self.ffi.engine_open(&mut engine);
            if open != 0 {
                return WfpProtection::<F>::failure("NATIVE_ENGINE_OPEN_FAILED", open, processes);
            }
            let mut outcome = ProtectionOutcome::default();
            for kind in kinds {
                if *kind == FilterKind::Block && sweep_loopback {
                    // permit 全部删完再删阻断：撤保护的过程中不出现「只剩放行」的窗口。
                    match self.owned_loopback_keys(engine, environment_ref) {
                        Ok(keys) => self.delete_keys(engine, &keys, &mut outcome),
                        Err(status) => {
                            outcome.code = Some("NATIVE_FILTER_ENUM_FAILED".to_string());
                            outcome.native_status = Some(i64::from(status));
                        }
                    }
                }
                let mut keys = Vec::new();
                for path in processes {
                    for v6 in [false, true] {
                        keys.push(derive_key(environment_ref, path, v6, *kind, ""));
                    }
                }
                self.delete_keys(engine, &keys, &mut outcome);
            }
            self.ffi.engine_close(engine);
            outcome
        }
    }
}

impl<F: WfpFfi> ProtectionBackend for WfpProtection<F> {
    fn ensure(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome {
        self.install_filters(environment_ref, processes, &FilterPlan::Baseline(loopback))
    }

    fn read(&self, environment_ref: &str, processes: &[String], loopback: &LoopbackPolicy) -> ProtectionOutcome {
        self.read_filters(environment_ref, processes, &FilterPlan::Baseline(loopback))
    }

    fn release(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        self.delete_derived(environment_ref, processes, &[FilterKind::ManagedPath, FilterKind::LegacyLoopback, FilterKind::Block], true)
    }

    fn resolve_interface(&self, alias: &str) -> Result<u64, ServiceError> {
        let wide_alias = wide(alias);
        let mut luid = 0u64;
        let status = unsafe { self.ffi.interface_alias_to_luid(wide_alias.as_ptr(), &mut luid) };
        if status != 0 || luid == 0 {
            return Err(ServiceError::new("MANAGED_INTERFACE_NOT_FOUND", format!("找不到内核报告的 TUN 接口（{status}）")));
        }
        Ok(luid)
    }

    fn open_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome {
        if interface_luid == 0 {
            return WfpProtection::<F>::failure("MANAGED_INTERFACE_NOT_FOUND", 0, processes);
        }
        self.install_filters(environment_ref, processes, &FilterPlan::ManagedPath(interface_luid))
    }

    fn read_managed_path(&self, environment_ref: &str, processes: &[String], interface_luid: u64) -> ProtectionOutcome {
        self.read_filters(environment_ref, processes, &FilterPlan::ManagedPath(interface_luid))
    }

    fn close_managed_path(&self, environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        self.delete_derived(environment_ref, processes, &[FilterKind::ManagedPath], false)
    }
}

/// 产品保护后端：Windows 上是真实 WFP；其他平台如实回报不可用，任何程序都算未覆盖。
pub fn product_protection() -> Box<dyn ProtectionBackend> {
    #[cfg(windows)]
    {
        Box::new(WfpProtection::new(WindowsFfi))
    }
    #[cfg(not(windows))]
    {
        Box::new(UnsupportedProtection)
    }
}

/// 卸载助手用的子层清扫：Windows 上是真实 WFP；其他平台如实回报不可用，不算撤净。
pub fn product_sublayer_sweep(release: bool) -> ProductSweep {
    #[cfg(windows)]
    {
        WfpProtection::new(WindowsFfi).sweep_product_sublayer(release)
    }
    #[cfg(not(windows))]
    {
        let _ = release;
        ProductSweep { code: Some("WFP_WINDOWS_ONLY".to_string()), ..ProductSweep::default() }
    }
}

#[cfg(not(windows))]
pub struct UnsupportedProtection;

#[cfg(not(windows))]
impl UnsupportedProtection {
    fn unavailable(processes: &[String]) -> ProtectionOutcome {
        ProtectionOutcome { missing: processes.to_vec(), code: Some("WFP_WINDOWS_ONLY".to_string()), ..ProtectionOutcome::default() }
    }
}

#[cfg(not(windows))]
impl ProtectionBackend for UnsupportedProtection {
    fn ensure(&self, _environment_ref: &str, processes: &[String], _loopback: &LoopbackPolicy) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
    fn read(&self, _environment_ref: &str, processes: &[String], _loopback: &LoopbackPolicy) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
    fn release(&self, _environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
    fn resolve_interface(&self, _alias: &str) -> Result<u64, ServiceError> {
        Err(ServiceError::new("WFP_WINDOWS_ONLY", "受管接口只在 Windows 上解析"))
    }
    fn open_managed_path(&self, _environment_ref: &str, processes: &[String], _interface_luid: u64) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
    fn read_managed_path(&self, _environment_ref: &str, processes: &[String], _interface_luid: u64) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
    fn close_managed_path(&self, _environment_ref: &str, processes: &[String]) -> ProtectionOutcome {
        UnsupportedProtection::unavailable(processes)
    }
}

#[cfg(windows)]
pub struct WindowsFfi;

#[cfg(windows)]
mod ffi {
    use super::{FwpByteBlob, FwpmFilter0, FwpmFilterEnumTemplate0, FwpmSubLayer0, Guid};
    use std::ffi::c_void;

    #[link(name = "fwpuclnt")]
    extern "system" {
        pub fn FwpmEngineOpen0(server_name: *const u16, authn_service: u32, auth_identity: *mut c_void, session: *const c_void, engine: *mut *mut c_void) -> i32;
        pub fn FwpmSubLayerAdd0(engine: *mut c_void, sublayer: *const FwpmSubLayer0, sd: *const c_void) -> i32;
        pub fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> i32;
        pub fn FwpmFilterAdd0(engine: *mut c_void, filter: *const FwpmFilter0, sd: *const c_void, id: *mut u64) -> i32;
        pub fn FwpmFilterGetByKey0(engine: *mut c_void, key: *const Guid, filter: *mut *mut FwpmFilter0) -> i32;
        pub fn FwpmFilterDeleteByKey0(engine: *mut c_void, key: *const Guid) -> i32;
        pub fn FwpmFilterCreateEnumHandle0(engine: *mut c_void, template: *const FwpmFilterEnumTemplate0, handle: *mut *mut c_void) -> i32;
        pub fn FwpmFilterEnum0(engine: *mut c_void, handle: *mut c_void, requested: u32, entries: *mut *mut *mut FwpmFilter0, returned: *mut u32) -> i32;
        pub fn FwpmFilterDestroyEnumHandle0(engine: *mut c_void, handle: *mut c_void) -> i32;
        pub fn FwpmSubLayerDeleteByKey0(engine: *mut c_void, key: *const Guid) -> i32;
        pub fn FwpmEngineClose0(engine: *mut c_void) -> i32;
        pub fn FwpmFreeMemory0(p: *mut *mut c_void);
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        pub fn ConvertInterfaceAliasToLuid(interface_alias: *const u16, interface_luid: *mut u64) -> u32;
    }
}

#[cfg(windows)]
impl WfpFfi for WindowsFfi {
    unsafe fn engine_open(&self, engine: *mut *mut c_void) -> i32 {
        ffi::FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT, ptr::null_mut(), ptr::null(), engine)
    }
    unsafe fn sublayer_add(&self, engine: *mut c_void, sublayer: *const FwpmSubLayer0) -> i32 {
        ffi::FwpmSubLayerAdd0(engine, sublayer, ptr::null())
    }
    unsafe fn get_app_id_from_file_name(&self, file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> i32 {
        ffi::FwpmGetAppIdFromFileName0(file_name, app_id)
    }
    unsafe fn filter_add(&self, engine: *mut c_void, filter: *const FwpmFilter0, id: *mut u64) -> i32 {
        ffi::FwpmFilterAdd0(engine, filter, ptr::null(), id)
    }
    unsafe fn filter_get_by_key(&self, engine: *mut c_void, key: *const Guid, filter: *mut *mut FwpmFilter0) -> i32 {
        ffi::FwpmFilterGetByKey0(engine, key, filter)
    }
    unsafe fn filter_delete_by_key(&self, engine: *mut c_void, key: *const Guid) -> i32 {
        ffi::FwpmFilterDeleteByKey0(engine, key)
    }
    unsafe fn filter_create_enum_handle(&self, engine: *mut c_void, template: *const FwpmFilterEnumTemplate0, handle: *mut *mut c_void) -> i32 {
        ffi::FwpmFilterCreateEnumHandle0(engine, template, handle)
    }
    unsafe fn filter_enum(&self, engine: *mut c_void, handle: *mut c_void, requested: u32, entries: *mut *mut *mut FwpmFilter0, returned: *mut u32) -> i32 {
        ffi::FwpmFilterEnum0(engine, handle, requested, entries, returned)
    }
    unsafe fn filter_destroy_enum_handle(&self, engine: *mut c_void, handle: *mut c_void) -> i32 {
        ffi::FwpmFilterDestroyEnumHandle0(engine, handle)
    }
    unsafe fn sublayer_delete_by_key(&self, engine: *mut c_void, key: *const Guid) -> i32 {
        ffi::FwpmSubLayerDeleteByKey0(engine, key)
    }
    unsafe fn engine_close(&self, engine: *mut c_void) -> i32 {
        ffi::FwpmEngineClose0(engine)
    }
    unsafe fn free_memory(&self, p: *mut *mut c_void) {
        ffi::FwpmFreeMemory0(p);
    }
    unsafe fn interface_alias_to_luid(&self, alias: *const u16, luid: *mut u64) -> u32 {
        ffi::ConvertInterfaceAliasToLuid(alias, luid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

    const CLAUDE: &str = r"C:\Program Files\Claude\claude.exe";
    const BROWSER: &str = r"C:\Program Files\Claude\claude-browser.exe";
    const OTHER: &str = r"C:\Tools\curl.exe";
    const TUN_LUID: u64 = 0x0000_0035_0000_0011;
    const WIFI_LUID: u64 = 0x0000_0047_0000_0003;
    const LOOPBACK_LUID: u64 = 0x0000_0018_0000_0001;
    const LOCALHOST: u32 = 0x7f00_0001;
    const OAUTH_PORT: u16 = 43123;
    /// 本机代理（例如 Clash Verge Rev）常见的混合端口，模板从不点名它。
    const CVR_PORT: u16 = 7897;
    /// 替身用来模拟读取或删除本身出错（RPC_S_SERVER_UNAVAILABLE 的 HRESULT），与「不存在」区分。
    const RPC_UNAVAILABLE: i32 = 0x8007_06bau32 as i32;

    #[derive(Clone, Debug)]
    struct StoredCondition {
        field_key: Guid,
        match_type: u32,
        data_type: u32,
        blob: Vec<u8>,
        uint64: u64,
    }

    /// 替身按 FwpmFilterAdd0 收到的结构体逐字段深拷贝，回读与枚举时再按同样布局重建。
    #[derive(Clone, Debug)]
    struct StoredFilter {
        key: Guid,
        layer: Guid,
        sublayer: Guid,
        action: u32,
        weight_type: u32,
        weight: usize,
        description: Option<String>,
        conditions: Vec<StoredCondition>,
    }

    struct RecordingFfi {
        calls: Mutex<Vec<&'static str>>,
        filters: Mutex<BTreeMap<Guid, StoredFilter>>,
        interfaces: Mutex<BTreeMap<String, u64>>,
        fail_on_add: Mutex<Option<usize>>,
        adds: Mutex<usize>,
        enums: Mutex<BTreeMap<usize, Vec<Guid>>>,
        next_enum: Mutex<usize>,
        fail_enum: Mutex<bool>,
        fail_get: Mutex<bool>,
        fail_delete: Mutex<bool>,
        fail_delete_key: Mutex<Option<Guid>>,
        deleted: Mutex<Vec<Guid>>,
    }

    impl RecordingFfi {
        fn new() -> RecordingFfi {
            let mut interfaces = BTreeMap::new();
            interfaces.insert("Meta".to_string(), TUN_LUID);
            interfaces.insert("Wi-Fi".to_string(), WIFI_LUID);
            RecordingFfi {
                calls: Mutex::new(vec![]),
                filters: Mutex::new(BTreeMap::new()),
                interfaces: Mutex::new(interfaces),
                fail_on_add: Mutex::new(None),
                adds: Mutex::new(0),
                enums: Mutex::new(BTreeMap::new()),
                next_enum: Mutex::new(0),
                fail_enum: Mutex::new(false),
                fail_get: Mutex::new(false),
                fail_delete: Mutex::new(false),
                fail_delete_key: Mutex::new(None),
                deleted: Mutex::new(Vec::new()),
            }
        }
    }

    unsafe fn wide_to_string(pointer: *const u16) -> String {
        read_wide(pointer).unwrap_or_default()
    }

    fn leak_wide(text: &str) -> *mut u16 {
        Box::leak(wide(text).into_boxed_slice()).as_mut_ptr()
    }

    fn materialize(stored: &StoredFilter) -> *mut FwpmFilter0 {
        let conditions: Vec<FwpmFilterCondition0> = stored
            .conditions
            .iter()
            .map(|condition| {
                let value = match condition.data_type {
                    FWP_BYTE_BLOB_TYPE => {
                        let bytes: &'static mut [u8] = Box::leak(condition.blob.clone().into_boxed_slice());
                        Box::into_raw(Box::new(FwpByteBlob { size: bytes.len() as u32, data: bytes.as_mut_ptr() })) as usize
                    }
                    FWP_BYTE_ARRAY16_TYPE => {
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&condition.blob);
                        Box::into_raw(Box::new(bytes)) as usize
                    }
                    FWP_UINT64 => Box::into_raw(Box::new(condition.uint64)) as usize,
                    _ => condition.uint64 as usize,
                };
                FwpmFilterCondition0 { field_key: condition.field_key, match_type: condition.match_type, condition_value: FwpValue0 { data_type: condition.data_type, value } }
            })
            .collect();
        let count = conditions.len() as u32;
        let conditions: &'static mut [FwpmFilterCondition0] = Box::leak(conditions.into_boxed_slice());
        Box::into_raw(Box::new(FwpmFilter0 {
            filter_key: stored.key,
            display_data: FwpmDisplayData0 { name: leak_wide(FILTER_NAME), description: stored.description.as_deref().map(leak_wide).unwrap_or(ptr::null_mut()) },
            flags: 0,
            provider_key: ptr::null_mut(),
            provider_data: FwpByteBlob { size: 0, data: ptr::null_mut() },
            layer_key: stored.layer,
            sub_layer_key: stored.sublayer,
            weight: FwpValue0 { data_type: stored.weight_type, value: stored.weight },
            num_filter_conditions: count,
            filter_condition: conditions.as_mut_ptr(),
            action: FwpmAction0 { action_type: stored.action, filter_type: ZERO_GUID },
            raw_context: 0,
            provider_context_pad: 0,
            reserved: ptr::null_mut(),
            filter_id: 1,
            effective_weight: FwpValue0 { data_type: FWP_EMPTY, value: 0 },
        }))
    }

    impl WfpFfi for RecordingFfi {
        unsafe fn engine_open(&self, engine: *mut *mut c_void) -> i32 {
            self.calls.lock().unwrap().push("FwpmEngineOpen0");
            *engine = 0x1 as *mut c_void;
            0
        }
        unsafe fn sublayer_add(&self, _engine: *mut c_void, _sublayer: *const FwpmSubLayer0) -> i32 {
            self.calls.lock().unwrap().push("FwpmSubLayerAdd0");
            FWP_E_ALREADY_EXISTS
        }
        unsafe fn get_app_id_from_file_name(&self, file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> i32 {
            let path = wide_to_string(file_name).to_lowercase();
            let device = format!(r"\device\harddiskvolume3{}", &path[2..]);
            let bytes: &'static mut [u8] = Box::leak(device.into_bytes().into_boxed_slice());
            *app_id = Box::into_raw(Box::new(FwpByteBlob { size: bytes.len() as u32, data: bytes.as_mut_ptr() }));
            0
        }
        unsafe fn filter_add(&self, _engine: *mut c_void, filter: *const FwpmFilter0, _id: *mut u64) -> i32 {
            self.calls.lock().unwrap().push("FwpmFilterAdd0");
            let mut adds = self.adds.lock().unwrap();
            *adds += 1;
            if *self.fail_on_add.lock().unwrap() == Some(*adds) {
                return 0x8032_0013u32 as i32;
            }
            let filter = &*filter;
            let raw = std::slice::from_raw_parts(filter.filter_condition, filter.num_filter_conditions as usize);
            let conditions = raw
                .iter()
                .map(|condition| {
                    let value = &condition.condition_value;
                    let (blob, uint64) = match value.data_type {
                        FWP_BYTE_BLOB_TYPE => {
                            let blob = &*(value.value as *const FwpByteBlob);
                            (std::slice::from_raw_parts(blob.data, blob.size as usize).to_vec(), 0)
                        }
                        FWP_BYTE_ARRAY16_TYPE => ((*(value.value as *const [u8; 16])).to_vec(), 0),
                        FWP_UINT64 => (Vec::new(), *(value.value as *const u64)),
                        _ => (Vec::new(), value.value as u64),
                    };
                    StoredCondition { field_key: condition.field_key, match_type: condition.match_type, data_type: value.data_type, blob, uint64 }
                })
                .collect();
            let stored = StoredFilter {
                key: filter.filter_key,
                layer: filter.layer_key,
                sublayer: filter.sub_layer_key,
                action: filter.action.action_type,
                weight_type: filter.weight.data_type,
                weight: filter.weight.value,
                description: read_wide(filter.display_data.description),
                conditions,
            };
            let mut filters = self.filters.lock().unwrap();
            if filters.contains_key(&stored.key) {
                return FWP_E_ALREADY_EXISTS;
            }
            filters.insert(stored.key, stored);
            0
        }
        unsafe fn filter_get_by_key(&self, _engine: *mut c_void, key: *const Guid, filter: *mut *mut FwpmFilter0) -> i32 {
            if *self.fail_get.lock().unwrap() {
                return RPC_UNAVAILABLE;
            }
            let Some(stored) = self.filters.lock().unwrap().get(&*key).cloned() else {
                return FWP_E_FILTER_NOT_FOUND;
            };
            *filter = materialize(&stored);
            0
        }
        unsafe fn filter_delete_by_key(&self, _engine: *mut c_void, key: *const Guid) -> i32 {
            self.calls.lock().unwrap().push("FwpmFilterDeleteByKey0");
            if *self.fail_delete.lock().unwrap() || *self.fail_delete_key.lock().unwrap() == Some(*key) {
                return RPC_UNAVAILABLE;
            }
            if self.filters.lock().unwrap().remove(&*key).is_some() {
                self.deleted.lock().unwrap().push(*key);
                0
            } else {
                FWP_E_FILTER_NOT_FOUND
            }
        }
        unsafe fn filter_create_enum_handle(&self, _engine: *mut c_void, template: *const FwpmFilterEnumTemplate0, handle: *mut *mut c_void) -> i32 {
            self.calls.lock().unwrap().push("FwpmFilterCreateEnumHandle0");
            if *self.fail_enum.lock().unwrap() {
                return 0x8032_0001u32 as i32;
            }
            let filters = self.filters.lock().unwrap();
            let snapshot: Vec<Guid> = if template.is_null() {
                filters.keys().copied().collect()
            } else {
                let template = &*template;
                assert_eq!(template.num_filter_conditions, 0, "按层取全部过滤器");
                assert_eq!(template.action_mask, ENUM_ANY_ACTION, "不按动作筛");
                filters.values().filter(|filter| filter.layer == template.layer_key).map(|filter| filter.key).collect()
            };
            drop(filters);
            let mut next = self.next_enum.lock().unwrap();
            *next += 1;
            self.enums.lock().unwrap().insert(*next, snapshot);
            *handle = *next as *mut c_void;
            0
        }
        unsafe fn filter_enum(&self, _engine: *mut c_void, handle: *mut c_void, requested: u32, entries: *mut *mut *mut FwpmFilter0, returned: *mut u32) -> i32 {
            self.calls.lock().unwrap().push("FwpmFilterEnum0");
            let batch: Vec<Guid> = {
                let mut enums = self.enums.lock().unwrap();
                let Some(pending) = enums.get_mut(&(handle as usize)) else {
                    return 0x8032_0002u32 as i32;
                };
                let take = pending.len().min(requested as usize);
                pending.drain(..take).collect()
            };
            let filters = self.filters.lock().unwrap();
            let pointers: Vec<*mut FwpmFilter0> = batch.iter().filter_map(|key| filters.get(key)).map(materialize).collect();
            *returned = pointers.len() as u32;
            let leaked: &'static mut [*mut FwpmFilter0] = Box::leak(pointers.into_boxed_slice());
            *entries = leaked.as_mut_ptr();
            0
        }
        unsafe fn filter_destroy_enum_handle(&self, _engine: *mut c_void, handle: *mut c_void) -> i32 {
            self.calls.lock().unwrap().push("FwpmFilterDestroyEnumHandle0");
            self.enums.lock().unwrap().remove(&(handle as usize));
            0
        }
        unsafe fn sublayer_delete_by_key(&self, _engine: *mut c_void, _key: *const Guid) -> i32 {
            self.calls.lock().unwrap().push("FwpmSubLayerDeleteByKey0");
            0
        }
        unsafe fn engine_close(&self, _engine: *mut c_void) -> i32 {
            self.calls.lock().unwrap().push("FwpmEngineClose0");
            0
        }
        unsafe fn free_memory(&self, _p: *mut *mut c_void) {
            self.calls.lock().unwrap().push("FwpmFreeMemory0");
        }
        unsafe fn interface_alias_to_luid(&self, alias: *const u16, luid: *mut u64) -> u32 {
            match self.interfaces.lock().unwrap().get(&wide_to_string(alias)) {
                Some(value) => {
                    *luid = *value;
                    0
                }
                None => 1168,
            }
        }
    }

    fn scope(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn app_id_of(path: &str) -> Vec<u8> {
        format!(r"\device\harddiskvolume3{}", &path.to_lowercase()[2..]).into_bytes()
    }

    fn endpoint(source: &str, transport: &str, address: &str, port: u16) -> LoopbackEndpoint {
        LoopbackEndpoint { source_process_path: source.to_string(), transport: transport.to_string(), address: address.to_string(), port, purpose: "oauth_callback".to_string() }
    }

    fn policy(version: &str, endpoints: Vec<LoopbackEndpoint>) -> LoopbackPolicy {
        LoopbackPolicy::new(Some(version.to_string()), endpoints)
    }

    fn no_endpoints() -> LoopbackPolicy {
        LoopbackPolicy::new(Some("template-v1".to_string()), Vec::new())
    }

    /// 直接写入上一版本安装的「批准程序全部回环放行」：ALE_APP_ID + FLAGS 含 IS_LOOPBACK，权重档 14。
    fn install_legacy(ffi: &RecordingFfi, environment_ref: &str, process: &str, v6: bool) {
        let key = legacy_loopback_filter_key(environment_ref, process, v6);
        ffi.filters.lock().unwrap().insert(
            key,
            StoredFilter {
                key,
                layer: layer_for(v6),
                sublayer: PRODUCT_SUBLAYER,
                action: FWP_ACTION_PERMIT,
                weight_type: FWP_UINT8,
                weight: usize::from(LOOPBACK_WEIGHT),
                description: Some(filter_marker(environment_ref, v6, FilterKind::LegacyLoopback)),
                conditions: vec![
                    StoredCondition { field_key: condition_ale_app_id(), match_type: FWP_MATCH_EQUAL, data_type: FWP_BYTE_BLOB_TYPE, blob: app_id_of(process), uint64: 0 },
                    StoredCondition { field_key: condition_flags(), match_type: FWP_MATCH_FLAGS_ALL_SET, data_type: FWP_UINT32, blob: Vec::new(), uint64: u64::from(FWP_CONDITION_FLAG_IS_LOOPBACK) },
                ],
            },
        );
    }

    /// 一次出站连接在 ALE_AUTH_CONNECT 上可见的字段。
    #[derive(Clone, Copy)]
    struct Connection {
        interface_luid: u64,
        flags: u32,
        protocol: u8,
        remote_v4: u32,
        remote_v6: [u8; 16],
        remote_port: u16,
    }

    const VIA_TUN: Connection = Connection {
        interface_luid: TUN_LUID,
        flags: 0,
        protocol: IPPROTO_TCP,
        remote_v4: 0xcb00_710a,
        remote_v6: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a],
        remote_port: 443,
    };
    const VIA_WIFI: Connection = Connection { interface_luid: WIFI_LUID, ..VIA_TUN };

    fn loopback(protocol: u8, remote_v4: u32, remote_port: u16) -> Connection {
        Connection { interface_luid: LOOPBACK_LUID, flags: FWP_CONDITION_FLAG_IS_LOOPBACK, protocol, remote_v4, remote_v6: Ipv6Addr::LOCALHOST.octets(), remote_port }
    }

    /// 按提交给 WFP 的过滤器结构体模拟本产品子层内的仲裁：条件全部匹配的过滤器里权重档最高者给出结论。
    fn arbitrate(ffi: &RecordingFfi, program: &str, v6: bool, connection: Connection) -> Option<u32> {
        let layer = layer_for(v6);
        let app_id = app_id_of(program);
        let filters = ffi.filters.lock().unwrap();
        let decided = filters
            .values()
            .filter(|filter| filter.layer == layer && filter.sublayer == PRODUCT_SUBLAYER)
            .filter(|filter| {
                filter.conditions.iter().all(|condition| {
                    let equal = condition.match_type == FWP_MATCH_EQUAL;
                    if condition.field_key == condition_ale_app_id() {
                        equal && condition.data_type == FWP_BYTE_BLOB_TYPE && condition.blob == app_id
                    } else if condition.field_key == condition_ip_local_interface() {
                        equal && condition.data_type == FWP_UINT64 && condition.uint64 == connection.interface_luid
                    } else if condition.field_key == condition_flags() {
                        let wanted = condition.uint64 as u32;
                        condition.match_type == FWP_MATCH_FLAGS_ALL_SET && condition.data_type == FWP_UINT32 && connection.flags & wanted == wanted
                    } else if condition.field_key == condition_ip_protocol() {
                        equal && condition.data_type == FWP_UINT8 && condition.uint64 as u8 == connection.protocol
                    } else if condition.field_key == condition_ip_remote_address() {
                        equal
                            && ((!v6 && condition.data_type == FWP_UINT32 && condition.uint64 as u32 == connection.remote_v4)
                                || (v6 && condition.data_type == FWP_BYTE_ARRAY16_TYPE && condition.blob == connection.remote_v6))
                    } else if condition.field_key == condition_ip_remote_port() {
                        equal && condition.data_type == FWP_UINT16 && condition.uint64 as u16 == connection.remote_port
                    } else {
                        false
                    }
                })
            })
            .max_by_key(|filter| (filter.weight_type == FWP_UINT8, filter.weight))
            .map(|filter| filter.action);
        decided
    }

    #[test]
    fn the_baseline_block_is_committed_with_its_full_semantics_and_readback_rejects_a_tampered_filter() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE, BROWSER]);
        let empty = no_endpoints();
        assert!(!protection.read("env-host", &processes, &empty).covers(&processes), "安装前回读不能算生效");
        let outcome = protection.ensure("env-host", &processes, &empty);
        assert_eq!(outcome.code, None);
        assert_eq!(outcome.created, 4, "空清单时每个程序每个协议栈只有一条阻断");
        {
            let filters = protection.ffi.filters.lock().unwrap();
            assert!(filters.values().all(|filter| filter.action == FWP_ACTION_BLOCK), "空清单不装任何 permit");
            for v6 in [false, true] {
                let stored = filters.get(&stable_filter_key("env-host", CLAUDE, v6)).expect("每个程序每个协议栈一条阻断");
                assert_eq!(stored.layer, layer_for(v6));
                assert_eq!(stored.sublayer, PRODUCT_SUBLAYER);
                assert_eq!(stored.action, FWP_ACTION_BLOCK);
                assert_eq!((stored.weight_type, stored.weight), (FWP_UINT8, usize::from(BLOCK_WEIGHT)));
                assert_eq!(stored.description.as_deref(), Some(filter_marker("env-host", v6, FilterKind::Block).as_str()));
                assert_eq!(stored.conditions.len(), 1);
                assert_eq!(stored.conditions[0].field_key, condition_ale_app_id());
                assert_eq!(stored.conditions[0].data_type, FWP_BYTE_BLOB_TYPE);
                assert_eq!(stored.conditions[0].blob, app_id_of(CLAUDE));
            }
        }
        let readback = protection.read("env-host", &processes, &empty);
        assert!(readback.covers(&processes));
        assert!(readback.residual.is_empty());
        assert_eq!(protection.ensure("env-host", &processes, &empty).created, 0, "同一环境重复保护是幂等的");
        assert!(protection.read("env-wsl", &processes, &empty).installed.is_empty(), "另一个环境的键不同");

        protection.ffi.filters.lock().unwrap().get_mut(&stable_filter_key("env-host", CLAUDE, true)).unwrap().action = FWP_ACTION_PERMIT;
        let tampered = protection.read("env-host", &processes, &empty);
        assert!(!tampered.covers(&processes), "键还在但动作被改成 permit，不能算生效");
        assert_eq!(tampered.mismatched, scope(&[CLAUDE]));
        protection.ffi.filters.lock().unwrap().get_mut(&stable_filter_key("env-host", BROWSER, false)).unwrap().conditions[0].blob = app_id_of(CLAUDE);
        assert_eq!(protection.read("env-host", &processes, &empty).mismatched, scope(&[CLAUDE, BROWSER]), "条件指向别的程序同样不算覆盖");

        assert_eq!(protection.ensure("env-host", &processes, &empty).code, None, "语义不符的同键过滤器被删掉重建");
        assert!(protection.read("env-host", &processes, &empty).covers(&processes));
    }

    #[test]
    fn an_empty_list_blocks_all_loopback_and_an_exact_endpoint_permits_only_itself() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE, BROWSER]);
        assert_eq!(protection.ensure("env-host", &processes, &no_endpoints()).code, None);
        for program in [CLAUDE, BROWSER] {
            assert_eq!(arbitrate(&protection.ffi, program, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_BLOCK), "空清单：回环全拦");
            assert_eq!(arbitrate(&protection.ffi, program, false, loopback(IPPROTO_TCP, LOCALHOST, CVR_PORT)), Some(FWP_ACTION_BLOCK));
            assert_eq!(arbitrate(&protection.ffi, program, true, loopback(IPPROTO_UDP, 0, 53)), Some(FWP_ACTION_BLOCK));
        }

        let oauth = endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT);
        let discovery = endpoint(CLAUDE, "udp", "::1", 5353);
        let current = policy("template-v2", vec![oauth.clone(), discovery.clone()]);
        let outcome = protection.ensure("env-host", &processes, &current);
        assert_eq!(outcome.code, None);
        assert_eq!(outcome.created, 2, "两条端点 permit，阻断已在");
        {
            let filters = protection.ffi.filters.lock().unwrap();
            assert_eq!(filters.values().filter(|filter| filter.action == FWP_ACTION_PERMIT).count(), 2, "只有模板点名的端点有 permit");
            let permit = filters.get(&loopback_endpoint_filter_key("env-host", CLAUDE, &oauth)).expect("IPv4 端点 permit");
            assert_eq!(permit.layer, layer_ale_auth_connect_v4(), "IPv4 端点只装在 v4 层");
            assert_eq!(permit.sublayer, PRODUCT_SUBLAYER);
            assert_eq!(permit.action, FWP_ACTION_PERMIT);
            assert_eq!((permit.weight_type, permit.weight), (FWP_UINT8, usize::from(LOOPBACK_WEIGHT)));
            assert_eq!(permit.description.as_deref(), Some(loopback_endpoint_marker("env-host", false, &current.digest).as_str()), "标记带策略摘要");
            let fields: Vec<Guid> = permit.conditions.iter().map(|condition| condition.field_key).collect();
            assert_eq!(fields, vec![condition_ale_app_id(), condition_flags(), condition_ip_protocol(), condition_ip_remote_address(), condition_ip_remote_port()], "程序、回环标志、协议、地址、端口同时绑定");
            assert_eq!(permit.conditions[0].blob, app_id_of(CLAUDE));
            assert_eq!((permit.conditions[1].match_type, permit.conditions[1].data_type, permit.conditions[1].uint64), (FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, u64::from(FWP_CONDITION_FLAG_IS_LOOPBACK)));
            assert_eq!((permit.conditions[2].match_type, permit.conditions[2].data_type, permit.conditions[2].uint64), (FWP_MATCH_EQUAL, FWP_UINT8, 6));
            assert_eq!((permit.conditions[3].match_type, permit.conditions[3].data_type, permit.conditions[3].uint64), (FWP_MATCH_EQUAL, FWP_UINT32, u64::from(LOCALHOST)), "IPv4 地址按主机字节序");
            assert_eq!((permit.conditions[4].match_type, permit.conditions[4].data_type, permit.conditions[4].uint64), (FWP_MATCH_EQUAL, FWP_UINT16, u64::from(OAUTH_PORT)));
            let v6_permit = filters.get(&loopback_endpoint_filter_key("env-host", CLAUDE, &discovery)).expect("IPv6 端点 permit");
            assert_eq!(v6_permit.layer, layer_ale_auth_connect_v6());
            assert_eq!(v6_permit.conditions[2].uint64, 17);
            assert_eq!((v6_permit.conditions[3].data_type, v6_permit.conditions[3].blob.clone()), (FWP_BYTE_ARRAY16_TYPE, Ipv6Addr::LOCALHOST.octets().to_vec()));
        }
        let readback = protection.read("env-host", &processes, &current);
        assert!(readback.covers(&processes), "{readback:?}");
        assert!(readback.residual.is_empty());

        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_PERMIT), "精确端点放行");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, true, loopback(IPPROTO_UDP, 0, 5353)), Some(FWP_ACTION_PERMIT), "IPv6 精确端点放行");
        assert_eq!(arbitrate(&protection.ffi, BROWSER, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_BLOCK), "错误程序被拦");
        assert_eq!(arbitrate(&protection.ffi, OTHER, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), None, "未批准程序不受本产品过滤器影响");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, 0x7f00_0002, OAUTH_PORT)), Some(FWP_ACTION_BLOCK), "错误地址被拦");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT + 1)), Some(FWP_ACTION_BLOCK), "错误端口被拦");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_UDP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_BLOCK), "错误协议被拦");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, CVR_PORT)), Some(FWP_ACTION_BLOCK), "本机代理端口被拦");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, true, loopback(IPPROTO_TCP, 0, OAUTH_PORT)), Some(FWP_ACTION_BLOCK), "端点只放行它自己的协议栈");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, Connection { flags: 0, ..loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT) }), Some(FWP_ACTION_BLOCK), "没有回环标志不算回环");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, VIA_WIFI), Some(FWP_ACTION_BLOCK), "端点 permit 不放行普通直连");

        let renamed = policy("template-v3", vec![oauth, discovery]);
        let stale = protection.read("env-host", &processes, &renamed);
        assert_eq!(stale.mismatched, scope(&[CLAUDE]), "模板版本变了，旧摘要的 permit 不算生效");
        assert!(!stale.covers(&processes));
        assert_eq!(protection.ensure("env-host", &processes, &renamed).code, None);
        assert!(protection.read("env-host", &processes, &renamed).covers(&processes));
    }

    #[test]
    fn shrinking_the_policy_deletes_old_permits_and_leftover_permits_fail_readback() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        let oauth = endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT);
        let helper = endpoint(CLAUDE, "tcp", "127.0.0.1", 43200);
        let wide_policy = policy("template-v1", vec![oauth.clone(), helper.clone()]);
        let narrow = policy("template-v2", vec![oauth.clone()]);
        assert_eq!(protection.ensure("env-host", &processes, &wide_policy).created, 4);
        assert!(protection.read("env-host", &processes, &wide_policy).covers(&processes));

        let before = protection.read("env-host", &processes, &narrow);
        assert_eq!(before.residual, vec![guid_text(&loopback_endpoint_filter_key("env-host", CLAUDE, &helper))], "旧端点 permit 是残留");
        assert!(!before.covers(&processes), "残留旧 permit 时缩减后的策略不算生效");

        let shrunk = protection.ensure("env-host", &processes, &narrow);
        assert_eq!(shrunk.code, None);
        assert_eq!(shrunk.removed, 1, "缩减删掉旧端点");
        let after = protection.read("env-host", &processes, &narrow);
        assert!(after.covers(&processes), "{after:?}");
        assert!(protection.ffi.filters.lock().unwrap().get(&loopback_endpoint_filter_key("env-host", CLAUDE, &helper)).is_none());
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, 43200)), Some(FWP_ACTION_BLOCK), "删掉的端点回到全拦");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_PERMIT));

        let emptied = protection.ensure("env-host", &processes, &no_endpoints());
        assert_eq!(emptied.removed, 1, "缩到空清单删掉最后一条端点 permit");
        assert!(protection.read("env-host", &processes, &no_endpoints()).covers(&processes));
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_BLOCK));

        assert_eq!(protection.ensure("env-host", &processes, &wide_policy).code, None);
        let leftover = protection.read("env-host", &processes, &no_endpoints());
        assert_eq!(leftover.residual.len(), 2, "服务记录是空清单而子层里还有端点 permit");
        assert_eq!(leftover.installed, processes, "阻断本身完整");
        assert!(!leftover.covers(&processes), "有残留 permit 就不算生效");
    }

    #[test]
    fn a_historical_all_loopback_permit_is_residual_until_migrated_away() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        assert_eq!(protection.ensure("env-host", &processes, &no_endpoints()).code, None);
        install_legacy(&protection.ffi, "env-host", CLAUDE, false);
        install_legacy(&protection.ffi, "env-host", CLAUDE, true);
        install_legacy(&protection.ffi, "env-wsl", BROWSER, false);
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, CVR_PORT)), Some(FWP_ACTION_PERMIT), "旧版全回环放行会放过本机代理端口");

        let readback = protection.read("env-host", &processes, &no_endpoints());
        assert_eq!(readback.installed, processes);
        assert_eq!(readback.residual.len(), 2);
        assert!(!readback.covers(&processes), "历史全回环放行还在就不算生效");

        let migrated = protection.ensure("env-host", &processes, &no_endpoints());
        assert_eq!(migrated.code, None);
        assert_eq!(migrated.removed, 2, "迁移删掉本环境的两条历史 permit");
        assert!(protection.read("env-host", &processes, &no_endpoints()).covers(&processes));
        for v6 in [false, true] {
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, loopback(IPPROTO_TCP, LOCALHOST, CVR_PORT)), Some(FWP_ACTION_BLOCK));
        }
        assert!(protection.ffi.filters.lock().unwrap().contains_key(&legacy_loopback_filter_key("env-wsl", BROWSER, false)), "另一个环境的过滤器不动");
    }

    #[test]
    fn tampered_or_missing_endpoint_permits_and_an_unreadable_sublayer_fail_readback() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        let oauth = endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT);
        let current = policy("template-v1", vec![oauth.clone()]);
        let key = loopback_endpoint_filter_key("env-host", CLAUDE, &oauth);
        assert_eq!(protection.ensure("env-host", &processes, &current).code, None);
        assert!(protection.read("env-host", &processes, &current).covers(&processes));

        fn port_to_cvr(filter: &mut StoredFilter) {
            filter.conditions[4].uint64 = u64::from(CVR_PORT);
        }
        fn address_changed(filter: &mut StoredFilter) {
            filter.conditions[3].uint64 = 0x7f00_0002;
        }
        fn protocol_dropped(filter: &mut StoredFilter) {
            filter.conditions.remove(2);
        }
        fn flag_match_changed(filter: &mut StoredFilter) {
            filter.conditions[1].match_type = FWP_MATCH_EQUAL;
        }
        fn program_changed(filter: &mut StoredFilter) {
            filter.conditions[0].blob = app_id_of(BROWSER);
        }
        fn action_changed(filter: &mut StoredFilter) {
            filter.action = FWP_ACTION_BLOCK;
        }
        fn marker_moved(filter: &mut StoredFilter) {
            filter.description = Some(loopback_endpoint_marker("env-wsl", false, &"0".repeat(64)));
        }
        let tampers: [(&str, fn(&mut StoredFilter)); 7] = [
            ("端口被改成本机代理端口", port_to_cvr),
            ("地址被改", address_changed),
            ("协议条件被删", protocol_dropped),
            ("回环标志的匹配方式被改", flag_match_changed),
            ("程序被改", program_changed),
            ("动作被改成阻断", action_changed),
            ("标记被改成另一个环境", marker_moved),
        ];
        for (label, tamper) in tampers {
            tamper(protection.ffi.filters.lock().unwrap().get_mut(&key).unwrap());
            let readback = protection.read("env-host", &processes, &current);
            assert_eq!(readback.mismatched, processes, "{label}：不算覆盖");
            assert!(!readback.covers(&processes), "{label}");
            assert_eq!(protection.ensure("env-host", &processes, &current).code, None, "{label}：重新保护时删掉重建");
            assert!(protection.read("env-host", &processes, &current).covers(&processes), "{label}：修复后回读通过");
        }

        protection.ffi.filters.lock().unwrap().remove(&key);
        let missing = protection.read("env-host", &processes, &current);
        assert_eq!(missing.mismatched, processes, "阻断在但缺端点 permit，集合不完整");
        assert!(!missing.covers(&processes));
        assert_eq!(protection.ensure("env-host", &processes, &current).created, 1);

        *protection.ffi.fail_enum.lock().unwrap() = true;
        let unreadable = protection.read("env-host", &processes, &current);
        assert_eq!(unreadable.residual, vec![RESIDUAL_UNVERIFIABLE.to_string()]);
        assert_eq!(unreadable.code.as_deref(), Some("NATIVE_FILTER_ENUM_FAILED"));
        assert!(!unreadable.covers(&processes), "证明不了没有残留，就不算生效");
        let ensured = protection.ensure("env-host", &processes, &current);
        assert_eq!(ensured.code.as_deref(), Some("NATIVE_FILTER_ENUM_FAILED"), "枚举失败如实回报");
        assert!(protection.ffi.filters.lock().unwrap().contains_key(&stable_filter_key("env-host", CLAUDE, false)), "枚举失败不影响阻断");
        *protection.ffi.fail_enum.lock().unwrap() = false;
        assert!(protection.read("env-host", &processes, &current).covers(&processes));
    }

    #[test]
    fn the_managed_path_permits_only_the_product_tun_interface_and_closing_it_leaves_the_baseline() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        let current = policy("template-v1", vec![endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT)]);
        assert_eq!(protection.ensure("env-host", &processes, &current).code, None);
        for v6 in [false, true] {
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_TUN), Some(FWP_ACTION_BLOCK), "只有基线时经 TUN 的连接也被拦");
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_WIFI), Some(FWP_ACTION_BLOCK));
        }
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_PERMIT), "只有基线时模板端点照样放行");

        let luid = protection.resolve_interface("Meta").unwrap();
        assert_eq!(luid, TUN_LUID);
        assert_eq!(protection.resolve_interface("Mihomo").unwrap_err().code, "MANAGED_INTERFACE_NOT_FOUND");
        let opened = protection.open_managed_path("env-host", &processes, luid);
        assert_eq!(opened.code, None);
        assert_eq!(opened.created, 2);
        {
            let filters = protection.ffi.filters.lock().unwrap();
            let permit = filters.get(&managed_path_filter_key("env-host", CLAUDE, false)).expect("受管路径 permit 已提交");
            assert_eq!(permit.action, FWP_ACTION_PERMIT);
            assert_eq!(permit.sublayer, PRODUCT_SUBLAYER, "与阻断同一子层，按权重仲裁");
            assert!(permit.weight > usize::from(LOOPBACK_WEIGHT) && LOOPBACK_WEIGHT > BLOCK_WEIGHT, "受管路径 > 回环端点 > 阻断");
            let fields: Vec<Guid> = permit.conditions.iter().map(|condition| condition.field_key).collect();
            assert_eq!(fields, vec![condition_ale_app_id(), condition_ip_local_interface()]);
            assert_eq!(permit.conditions[1].data_type, FWP_UINT64);
            assert_eq!(permit.conditions[1].uint64, TUN_LUID);
        }
        assert!(protection.read_managed_path("env-host", &processes, TUN_LUID).covers(&processes));
        assert_eq!(protection.read_managed_path("env-host", &processes, WIFI_LUID).mismatched, processes, "接口不同不算受管路径");
        assert!(protection.read("env-host", &processes, &current).covers(&processes), "受管路径打开时基线仍在，且受管 permit 不算回环残留");

        for v6 in [false, true] {
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_TUN), Some(FWP_ACTION_PERMIT), "正常：经本产品 TUN 的连接放行");
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_WIFI), Some(FWP_ACTION_BLOCK), "正常：经物理网卡的未知直连仍被拦");
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, Connection { flags: 0x0000_0002, ..VIA_WIFI }), Some(FWP_ACTION_BLOCK), "别的标志不能冒充回环");
        }
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, CVR_PORT)), Some(FWP_ACTION_BLOCK), "受管路径打开时本机代理端口仍被拦");
        assert_eq!(arbitrate(&protection.ffi, BROWSER, false, VIA_WIFI), None, "未批准程序不受本产品过滤器影响");

        let closed = protection.close_managed_path("env-host", &processes);
        assert_eq!(closed.removed, 2);
        assert!(protection.read_managed_path("env-host", &processes, TUN_LUID).installed.is_empty());
        assert!(protection.read("env-host", &processes, &current).covers(&processes), "关受管路径不撤阻断和端点 permit");
        for v6 in [false, true] {
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_TUN), Some(FWP_ACTION_BLOCK), "故障：受管路径关闭后经 TUN 的连接也被拦");
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_WIFI), Some(FWP_ACTION_BLOCK), "故障：物理网卡仍被拦");
        }
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, loopback(IPPROTO_TCP, LOCALHOST, OAUTH_PORT)), Some(FWP_ACTION_PERMIT), "故障：回环端点策略不变");

        protection.open_managed_path("env-host", &processes, TUN_LUID);
        let moved = protection.open_managed_path("env-host", &processes, 0x0000_0035_0000_0012);
        assert_eq!(moved.code, None);
        assert!(protection.read_managed_path("env-host", &processes, 0x0000_0035_0000_0012).covers(&processes), "内核换了接口，permit 跟着换");
        assert_eq!(arbitrate(&protection.ffi, CLAUDE, false, VIA_TUN), Some(FWP_ACTION_BLOCK), "旧接口不再放行");
    }

    #[test]
    fn a_failed_add_rolls_back_only_what_this_call_created() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let first = scope(&[CLAUDE]);
        let empty = no_endpoints();
        assert_eq!(protection.ensure("env-host", &first, &empty).code, None);
        let both = scope(&[CLAUDE, BROWSER]);
        let adds = *protection.ffi.adds.lock().unwrap();
        // 第二次 ensure：CLAUDE 两条阻断已在（第 1、2 次返回已存在），BROWSER 阻断 v4 新建（第 3 次），v6 失败（第 4 次）。
        *protection.ffi.fail_on_add.lock().unwrap() = Some(adds + 4);
        let outcome = protection.ensure("env-host", &both, &empty);
        assert_eq!(outcome.code.as_deref(), Some("NATIVE_FILTER_ADD_FAILED"));
        assert!(outcome.rolled_back);
        let readback = protection.read("env-host", &both, &empty);
        assert_eq!(readback.installed, first, "先前有效的保护还在");
        assert_eq!(readback.missing, scope(&[BROWSER]), "本次新建的 BROWSER 阻断已回滚");
        assert!(!readback.covers(&both));

        let current = policy("template-v1", vec![endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT)]);
        let adds = *protection.ffi.adds.lock().unwrap();
        // CLAUDE 两条阻断已在（第 1、2 次），端点 permit 失败（第 3 次）。
        *protection.ffi.fail_on_add.lock().unwrap() = Some(adds + 3);
        let failed = protection.ensure("env-host", &first, &current);
        assert!(failed.rolled_back);
        assert!(protection.ffi.filters.lock().unwrap().contains_key(&stable_filter_key("env-host", CLAUDE, true)), "端点 permit 失败不撤已有阻断");
        assert_eq!(protection.read("env-host", &first, &current).mismatched, first, "缺端点 permit 不算覆盖");

        *protection.ffi.fail_on_add.lock().unwrap() = None;
        let adds = *protection.ffi.adds.lock().unwrap();
        *protection.ffi.fail_on_add.lock().unwrap() = Some(adds + 2);
        let path = protection.open_managed_path("env-host", &first, TUN_LUID);
        assert!(path.rolled_back);
        assert!(protection.read_managed_path("env-host", &first, TUN_LUID).installed.is_empty(), "受管路径部分失败时保持关闭");
        assert!(protection.read("env-host", &first, &empty).covers(&first));
    }

    #[test]
    fn release_removes_only_this_environments_owned_filters_including_loopback_permits() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        let current = policy("template-v1", vec![endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT)]);
        assert_eq!(protection.ensure("env-host", &processes, &current).created, 3);
        protection.open_managed_path("env-host", &processes, TUN_LUID);
        install_legacy(&protection.ffi, "env-host", CLAUDE, false);
        protection.ensure("env-wsl", &processes, &current);
        let released = protection.release("env-host", &processes);
        assert_eq!(released.code, None);
        assert_eq!(released.removed, 6, "阻断、端点 permit、历史全回环放行与受管路径一起撤");
        let after = protection.read("env-host", &processes, &no_endpoints());
        assert!(after.installed.is_empty());
        assert!(after.mismatched.is_empty(), "不留半套基线");
        assert!(after.residual.is_empty(), "不留回环 permit");
        assert!(protection.read_managed_path("env-host", &processes, TUN_LUID).installed.is_empty());
        assert!(protection.read("env-wsl", &processes, &current).covers(&processes), "另一个环境的保护不受影响");
        assert!(!protection.ffi.calls.lock().unwrap().contains(&"FwpmSubLayerDeleteByKey0"), "共享子层不随单个环境撤销删除");
        let invalid = protection.ensure("env-host", &scope(&["claude.exe"]), &no_endpoints());
        assert_eq!(invalid.code.as_deref(), Some("PROCESS_SCOPE_INVALID"));
    }

    #[test]
    fn markers_attribute_loopback_permits_to_exactly_one_environment() {
        let digest = "a".repeat(64);
        assert!(owned_loopback_marker(&loopback_endpoint_marker("env-host", false, &digest), "env-host"));
        assert!(owned_loopback_marker(&filter_marker("env-host", true, FilterKind::LegacyLoopback), "env-host"));
        assert!(!owned_loopback_marker(&loopback_endpoint_marker("env-host-2", false, &digest), "env-host"));
        assert!(!owned_loopback_marker(&loopback_endpoint_marker("x|env-host", false, &digest), "env-host"));
        assert!(!owned_loopback_marker(&filter_marker("env-host", false, FilterKind::ManagedPath), "env-host"), "受管路径 permit 不是回环残留");
        assert!(!owned_loopback_marker(&filter_marker("env-host", false, FilterKind::Block), "env-host"));
        assert!(!owned_loopback_marker("steward|loopback-endpoint|v4|short|env-host", "env-host"));
    }

    #[test]
    fn the_sweep_removes_every_product_filter_whatever_the_records_say() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let current = policy("template-v1", vec![endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT)]);
        assert_eq!(protection.ensure("env-host", &scope(&[CLAUDE]), &current).created, 3);
        assert_eq!(protection.open_managed_path("env-host", &scope(&[CLAUDE]), TUN_LUID).created, 2);
        assert_eq!(protection.ensure("env-forgotten", &scope(&[BROWSER]), &no_endpoints()).created, 2, "运行状态里已经没有记录的环境");
        install_legacy(&protection.ffi, "env-old", OTHER, false);
        let foreign = Guid { data1: 0x00fe_ed00, ..ZERO_GUID };
        protection.ffi.filters.lock().unwrap().insert(
            foreign,
            StoredFilter {
                key: foreign,
                layer: layer_ale_auth_connect_v4(),
                sublayer: Guid { data1: 0x1234, ..ZERO_GUID },
                action: FWP_ACTION_BLOCK,
                weight_type: FWP_UINT8,
                weight: 1,
                description: None,
                conditions: Vec::new(),
            },
        );
        let blocks: Vec<Guid> = protection.ffi.filters.lock().unwrap().values().filter(|filter| filter.sublayer == PRODUCT_SUBLAYER && filter.action == FWP_ACTION_BLOCK).map(|filter| filter.key).collect();

        let counted = protection.sweep_product_sublayer(false);
        assert_eq!((counted.found, counted.removed, counted.remaining), (8, 0, 8), "只数不删：阻断 4、端点 1、受管路径 2、历史回环 1");
        assert!(!counted.clean(), "还有本产品过滤器就不算干净");

        let swept = protection.sweep_product_sublayer(true);
        assert_eq!(swept.code, None);
        assert_eq!((swept.found, swept.removed, swept.remaining), (8, 8, 0));
        assert!(swept.clean());
        assert_eq!(protection.ffi.filters.lock().unwrap().keys().copied().collect::<Vec<_>>(), vec![foreign], "别的子层的过滤器不动");
        let deleted = protection.ffi.deleted.lock().unwrap().clone();
        let first_block = deleted.iter().position(|key| blocks.contains(key)).unwrap();
        assert!(deleted[first_block..].iter().all(|key| blocks.contains(key)), "permit 全部删完才删阻断");
        assert!(protection.sweep_product_sublayer(false).clean(), "清扫后再数一次为零");
    }

    #[test]
    fn an_enumeration_or_delete_failure_is_never_a_clean_sweep() {
        let protection = WfpProtection::new(RecordingFfi::new());
        assert_eq!(protection.ensure("env-host", &scope(&[CLAUDE]), &no_endpoints()).created, 2);
        *protection.ffi.fail_enum.lock().unwrap() = true;
        let unreadable = protection.sweep_product_sublayer(true);
        assert_eq!(unreadable.code.as_deref(), Some("NATIVE_FILTER_ENUM_FAILED"));
        assert_eq!(unreadable.remaining, 0, "数量是零");
        assert!(!unreadable.clean(), "枚举不了就证明不了撤净，数量为零也不算");
        assert_eq!(protection.ffi.filters.lock().unwrap().len(), 2, "枚举失败时什么都不删");
        *protection.ffi.fail_enum.lock().unwrap() = false;

        *protection.ffi.fail_delete.lock().unwrap() = true;
        let stuck = protection.sweep_product_sublayer(true);
        assert_eq!(stuck.code.as_deref(), Some("NATIVE_FILTER_DELETE_FAILED"));
        assert_eq!((stuck.found, stuck.removed, stuck.remaining), (2, 0, 2));
        assert!(!stuck.clean());
        *protection.ffi.fail_delete.lock().unwrap() = false;

        assert!(protection.sweep_product_sublayer(true).clean());
        assert!(protection.sweep_product_sublayer(false).clean(), "空子层只数不删也是干净的");
    }

    #[test]
    fn a_read_error_is_not_absence() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        assert_eq!(protection.read("env-host", &processes, &no_endpoints()).missing, processes, "没装时是缺");
        *protection.ffi.fail_get.lock().unwrap() = true;
        let unknown = protection.read("env-host", &processes, &no_endpoints());
        assert_eq!(unknown.code.as_deref(), Some("NATIVE_FILTER_READ_FAILED"));
        assert_eq!(unknown.native_status, Some(i64::from(RPC_UNAVAILABLE)));
        assert_eq!(unknown.mismatched, processes, "读不出来不算不在");
        assert!(unknown.missing.is_empty());
        assert!(!unknown.covers(&processes));
        let path = protection.read_managed_path("env-host", &processes, 0);
        assert_eq!(path.code.as_deref(), Some("NATIVE_FILTER_READ_FAILED"));
        assert_eq!(path.mismatched, processes, "受管路径回读同样不把读错当成撤净");
        *protection.ffi.fail_get.lock().unwrap() = false;
        assert_eq!(protection.ensure("env-host", &processes, &no_endpoints()).code, None);
        assert!(protection.read("env-host", &processes, &no_endpoints()).covers(&processes));
    }

    #[test]
    fn a_permit_that_cannot_be_deleted_keeps_every_block() {
        let protection = WfpProtection::new(RecordingFfi::new());
        let processes = scope(&[CLAUDE]);
        let oauth = endpoint(CLAUDE, "tcp", "127.0.0.1", OAUTH_PORT);
        assert_eq!(protection.ensure("env-host", &processes, &policy("template-v1", vec![oauth.clone()])).created, 3);
        assert_eq!(protection.open_managed_path("env-host", &processes, TUN_LUID).created, 2);
        let stuck = loopback_endpoint_filter_key("env-host", CLAUDE, &oauth);
        *protection.ffi.fail_delete_key.lock().unwrap() = Some(stuck);

        let swept = protection.sweep_product_sublayer(true);
        assert_eq!(swept.code.as_deref(), Some("NATIVE_FILTER_DELETE_FAILED"));
        assert!(!swept.clean());
        assert_eq!((swept.found, swept.removed, swept.remaining), (5, 2, 3), "只删掉两条受管路径 permit；删不掉的端点 permit 与两条阻断都还在");
        {
            let filters = protection.ffi.filters.lock().unwrap();
            for v6 in [false, true] {
                assert!(filters.contains_key(&stable_filter_key("env-host", CLAUDE, v6)), "permit 没删净时一条阻断都不删");
            }
            assert!(filters.contains_key(&stuck));
        }
        for v6 in [false, true] {
            assert_eq!(arbitrate(&protection.ffi, CLAUDE, v6, VIA_WIFI), Some(FWP_ACTION_BLOCK), "卸载失败后受保护程序仍被拦");
        }

        *protection.ffi.fail_delete_key.lock().unwrap() = None;
        let retried = protection.sweep_product_sublayer(true);
        assert!(retried.clean(), "{retried:?}");
        assert_eq!((retried.found, retried.removed), (3, 3), "重试时删掉剩下的 permit 与阻断");
    }
}
