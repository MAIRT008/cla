//! 宿主侧客户端（改写上游 `client/mod.rs`）：不再发送所有人都知道的固定 magic 文本，
//! 改为结构化请求（改写类命令带宿主签发的 envelope）；不提供 start_clash/stop_clash 这类原语。
//! 线上格式与服务端一致：每个连接发一帧请求、收一帧回执（4 字节大端长度 + JSON）。
//!
//! 双向认证：服务按 Windows 给出的客户端进程核对宿主；客户端不接受任意同名 pipe——
//! 打开后先用 `GetSecurityInfo` 读 pipe 对象的所有者 SID（Microsoft 明确列出该函数支持命名管道句柄，句柄需 READ_CONTROL），
//! 必须是服务在安全描述符里声明的 LocalSystem，通过才写第一个请求字节。
//! 打开 pipe 只请求 `PIPE_CLIENT_ACCESS`（含 READ_CONTROL，不含 FILE_CREATE_PIPE_INSTANCE）；tokio 的 `ClientOptions`
//! 固定请求 GENERIC_WRITE，在收窄后的 ACL 下会被拒，所以这里自己调用 `CreateFileW`，再交给 tokio 做异步读写。
//! 同步接口：在独立线程里建 current-thread 运行时，调用方无论是否在异步运行时里都不会嵌套阻塞。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::command::ServiceCommand;
use crate::core::network::authorize_service_server;
use crate::core::structure::{encode_frame, frame_length, ServiceError, ServiceReply, ServiceRequest, WireRequest};

pub fn call(command: ServiceCommand, request: &ServiceRequest, timeout: Duration) -> Result<ServiceReply, ServiceError> {
    let request = request.clone();
    let worker = std::thread::spawn(move || -> Result<ServiceReply, ServiceError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| ServiceError::new("SERVICE_CLIENT_RUNTIME", error.to_string()))?;
        runtime.block_on(async move {
            match tokio::time::timeout(timeout, connect_and_exchange(command, request)).await {
                Ok(result) => result,
                Err(_) => Err(ServiceError::new("SERVICE_TIMEOUT", "产品服务没有在时限内回复")),
            }
        })
    });
    worker
        .join()
        .map_err(|_| ServiceError::new("SERVICE_CLIENT_FAILED", "服务客户端线程异常结束"))?
}

/// 服务端核对通过才写请求帧、读回执帧；核对不过直接返回，连接上一个字节都不写。
pub async fn exchange_after_check<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_check: Result<(), ServiceError>,
    command: ServiceCommand,
    request: ServiceRequest,
) -> Result<ServiceReply, ServiceError> {
    server_check?;
    let broken = |detail: String| ServiceError::new("SERVICE_UNREACHABLE", detail);
    let frame = encode_frame(&WireRequest { command: command.name().to_string(), request })?;
    stream.write_all(&frame).await.map_err(|error| broken(error.to_string()))?;
    stream.flush().await.map_err(|error| broken(error.to_string()))?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|error| broken(error.to_string()))?;
    let mut body = vec![0u8; frame_length(header)?];
    stream.read_exact(&mut body).await.map_err(|error| broken(error.to_string()))?;
    serde_json::from_slice::<ServiceReply>(&body).map_err(|_| ServiceError::new("SERVICE_REPLY_INVALID", "服务返回了无法解析的回执"))
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    pub const OPEN_EXISTING: u32 = 3;
    pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    pub const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    pub const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    pub const ERROR_PIPE_BUSY: u32 = 231;
    pub const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    pub const SE_KERNEL_OBJECT: i32 = 6;
    pub const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        pub fn GetLastError() -> u32;
        pub fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        pub fn GetSecurityInfo(
            handle: *mut c_void,
            object_type: i32,
            security_info: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            security_descriptor: *mut *mut c_void,
        ) -> u32;
        pub fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    }
}

/// pipe 对象所有者的字符串 SID；任何一步失败都返回 None，由核对函数按「读不到身份」拒绝。
#[cfg(windows)]
fn pipe_owner_sid(pipe: *mut std::ffi::c_void) -> Option<String> {
    unsafe {
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = win::GetSecurityInfo(
            pipe,
            win::SE_KERNEL_OBJECT,
            win::OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if status != 0 || owner.is_null() {
            if !descriptor.is_null() {
                win::LocalFree(descriptor);
            }
            return None;
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        let converted = win::ConvertSidToStringSidW(owner, &mut text) != 0 && !text.is_null();
        let sid = if converted {
            let mut length = 0usize;
            while *text.add(length) != 0 && length < 256 {
                length += 1;
            }
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(text, length)))
        } else {
            None
        };
        if !text.is_null() {
            win::LocalFree(text as *mut std::ffi::c_void);
        }
        win::LocalFree(descriptor);
        sid
    }
}

#[cfg(windows)]
async fn connect_and_exchange(command: ServiceCommand, request: ServiceRequest) -> Result<ServiceReply, ServiceError> {
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use tokio::net::windows::named_pipe::NamedPipeClient;

    use crate::core::paths::{PIPE_CLIENT_ACCESS, SERVICE_PIPE};

    let unreachable = |detail: String| ServiceError::new("SERVICE_UNREACHABLE", detail);
    let name: Vec<u16> = SERVICE_PIPE.encode_utf16().chain(std::iter::once(0)).collect();
    let mut client = loop {
        let opened = unsafe {
            win::CreateFileW(
                name.as_ptr(),
                PIPE_CLIENT_ACCESS,
                0,
                std::ptr::null_mut(),
                win::OPEN_EXISTING,
                win::SECURITY_SQOS_PRESENT | win::SECURITY_IDENTIFICATION | win::FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if opened != win::INVALID_HANDLE_VALUE {
            break unsafe { NamedPipeClient::from_raw_handle(opened as RawHandle) }.map_err(|error| unreachable(error.to_string()))?;
        }
        let error = unsafe { win::GetLastError() };
        if error != win::ERROR_PIPE_BUSY {
            return Err(unreachable(format!("CreateFileW 失败：{error}")));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let owner = pipe_owner_sid(client.as_raw_handle() as *mut std::ffi::c_void);
    let verdict = authorize_service_server(owner.as_deref());
    exchange_after_check(&mut client, verdict, command, request).await
}

#[cfg(not(windows))]
async fn connect_and_exchange(_command: ServiceCommand, _request: ServiceRequest) -> Result<ServiceReply, ServiceError> {
    Err(ServiceError::new("SERVICE_UNREACHABLE", "产品服务只在 Windows 上运行"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::core::paths::{PRODUCT_APP_ID, PROTOCOL, SERVICE_PIPE_OWNER_SID};

    fn request() -> ServiceRequest {
        ServiceRequest { product_id: PRODUCT_APP_ID.to_string(), protocol: PROTOCOL.to_string(), envelope: None, payload: json!({"environment_ref": "env-host"}) }
    }

    #[test]
    fn a_pipe_not_owned_by_local_system_gets_no_request_bytes() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for (owner, code) in [
                (Some("S-1-5-21-1000-2000-3000-1001"), "SERVICE_SERVER_NOT_PRODUCT_SERVICE"),
                (Some("S-1-5-32-544"), "SERVICE_SERVER_NOT_PRODUCT_SERVICE"),
                (None, "SERVICE_SERVER_IDENTITY_UNAVAILABLE"),
            ] {
                let (mut client, mut impostor) = tokio::io::duplex(64 * 1024);
                let refused = exchange_after_check(&mut client, authorize_service_server(owner), ServiceCommand::ApplyConfig, request()).await;
                assert_eq!(refused.unwrap_err().code, code);
                drop(client);
                let mut received = Vec::new();
                impostor.read_to_end(&mut received).await.unwrap();
                assert!(received.is_empty(), "核对不过时服务端一个请求字节都收不到（{code}）");
            }
        });
    }

    #[test]
    fn a_pipe_owned_by_local_system_receives_the_request_and_its_reply_is_accepted() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let (mut client, mut service) = tokio::io::duplex(64 * 1024);
            let answering = tokio::spawn(async move {
                let mut header = [0u8; 4];
                service.read_exact(&mut header).await.unwrap();
                let mut body = vec![0u8; frame_length(header).unwrap()];
                service.read_exact(&mut body).await.unwrap();
                let wire: WireRequest = serde_json::from_slice(&body).unwrap();
                let reply = encode_frame(&ServiceReply::success(json!({"answered": wire.command}))).unwrap();
                service.write_all(&reply).await.unwrap();
            });
            let reply = exchange_after_check(&mut client, authorize_service_server(Some(SERVICE_PIPE_OWNER_SID)), ServiceCommand::Handshake, request())
                .await
                .unwrap();
            assert!(reply.ok);
            assert_eq!(reply.receipt["answered"], "Handshake");
            answering.await.unwrap();
        });
    }
}
