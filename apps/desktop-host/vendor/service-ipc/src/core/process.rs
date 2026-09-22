//! 进程身份、核验后结束与受保护程序探针（改写上游 `process.rs`）。
//!
//! 上游按 tasklist 判活、taskkill /PID /T /F 强杀；PID 会被系统复用，这里改为：
//! - 身份 = PID + 创建时间 + 程序完整路径，都从同一个进程句柄读出；
//! - 结束前持有这个句柄重新读身份并调用 `judge_termination`，一致才 TerminateProcess。持有句柄期间 PID 不会被复用；
//! - 只结束记录里的那一个进程，不按进程名批量结束，也不带 /T 结束整棵树。

use std::path::PathBuf;
use std::process::Command;

use crate::core::network::{PeerProcess, ProcessIdentity, ProcessProbe, TerminateOutcome};
use crate::core::structure::ServiceError;

#[cfg(windows)]
use crate::core::network::{judge_termination, TerminationJudgement};

fn system32(tool: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join(tool)
}

/// FILETIME（1601-01-01 起的 100 纳秒）换成 Unix 毫秒。
pub fn filetime_to_unix_ms(low: u32, high: u32) -> i64 {
    let ticks = (u64::from(high) << 32) | u64::from(low);
    (ticks as i64 - 116_444_736_000_000_000) / 10_000
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    pub const PROCESS_TERMINATE: u32 = 0x0001;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
    pub const ERROR_INVALID_PARAMETER: u32 = 87;

    #[repr(C)]
    #[derive(Default)]
    pub struct FileTime {
        pub low: u32,
        pub high: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> *mut c_void;
        pub fn GetProcessTimes(process: *mut c_void, creation: *mut FileTime, exit: *mut FileTime, kernel: *mut FileTime, user: *mut FileTime) -> i32;
        pub fn QueryFullProcessImageNameW(process: *mut c_void, flags: u32, name: *mut u16, size: *mut u32) -> i32;
        pub fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
        pub fn WaitForSingleObject(object: *mut c_void, milliseconds: u32) -> u32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn GetLastError() -> u32;
        pub fn GetNamedPipeClientProcessId(pipe: *mut c_void, client_process_id: *mut u32) -> i32;
    }
}

#[cfg(windows)]
struct ProcessHandle(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            win::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
enum Opened {
    Handle(ProcessHandle),
    Gone,
    Error(String),
}

#[cfg(windows)]
fn open_process(pid: u32, access: u32) -> Opened {
    let handle = unsafe { win::OpenProcess(access, 0, pid) };
    if handle.is_null() {
        let error = unsafe { win::GetLastError() };
        return if error == win::ERROR_INVALID_PARAMETER { Opened::Gone } else { Opened::Error(format!("PROCESS_OPEN_FAILED_{error}")) };
    }
    Opened::Handle(ProcessHandle(handle))
}

#[cfg(windows)]
fn read_identity(pid: u32, handle: &ProcessHandle) -> Result<Option<ProcessIdentity>, ServiceError> {
    unsafe {
        if win::WaitForSingleObject(handle.0, 0) != win::WAIT_TIMEOUT {
            return Ok(None);
        }
        let mut creation = win::FileTime::default();
        let mut exit = win::FileTime::default();
        let mut kernel = win::FileTime::default();
        let mut user = win::FileTime::default();
        if win::GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) == 0 {
            return Err(ServiceError::new("PROCESS_TIMES_UNAVAILABLE", format!("GetProcessTimes 失败：{}", win::GetLastError())));
        }
        let mut buffer = vec![0u16; 32_768];
        let mut size = buffer.len() as u32;
        if win::QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut size) == 0 {
            return Err(ServiceError::new("PROCESS_IMAGE_UNAVAILABLE", format!("QueryFullProcessImageNameW 失败：{}", win::GetLastError())));
        }
        let image_path = String::from_utf16_lossy(&buffer[..size as usize]);
        Ok(Some(ProcessIdentity { pid, image_path, created_at_ms: filetime_to_unix_ms(creation.low, creation.high) }))
    }
}

#[cfg(windows)]
pub fn identify_process(pid: u32) -> Result<Option<ProcessIdentity>, ServiceError> {
    match open_process(pid, win::PROCESS_QUERY_LIMITED_INFORMATION | win::SYNCHRONIZE) {
        Opened::Handle(handle) => read_identity(pid, &handle),
        Opened::Gone => Ok(None),
        Opened::Error(code) => Err(ServiceError::new(&code, "无法打开进程读取身份")),
    }
}

#[cfg(not(windows))]
pub fn identify_process(_pid: u32) -> Result<Option<ProcessIdentity>, ServiceError> {
    Err(ServiceError::new("PROCESS_IDENTITY_WINDOWS_ONLY", "进程身份只在 Windows 上读取"))
}

#[cfg(windows)]
pub fn terminate_owned(expected: &ProcessIdentity) -> TerminateOutcome {
    let query = match open_process(expected.pid, win::PROCESS_QUERY_LIMITED_INFORMATION | win::SYNCHRONIZE) {
        Opened::Handle(handle) => handle,
        Opened::Gone => return TerminateOutcome::NotRunning,
        Opened::Error(code) => return TerminateOutcome::Failed(code),
    };
    let actual = match read_identity(expected.pid, &query) {
        Ok(actual) => actual,
        Err(error) => return TerminateOutcome::Failed(error.code),
    };
    match judge_termination(expected, actual.as_ref()) {
        TerminationJudgement::NotRunning => TerminateOutcome::NotRunning,
        TerminationJudgement::Mismatch(actual) => TerminateOutcome::IdentityMismatch(actual),
        TerminationJudgement::Proceed => {
            let terminator = match open_process(expected.pid, win::PROCESS_TERMINATE | win::SYNCHRONIZE) {
                Opened::Handle(handle) => handle,
                Opened::Gone => return TerminateOutcome::NotRunning,
                Opened::Error(code) => return TerminateOutcome::Failed(code),
            };
            let outcome = unsafe {
                if win::TerminateProcess(terminator.0, 1) == 0 {
                    TerminateOutcome::Failed(format!("PROCESS_TERMINATE_FAILED_{}", win::GetLastError()))
                } else if win::WaitForSingleObject(terminator.0, 5_000) == win::WAIT_OBJECT_0 {
                    TerminateOutcome::Terminated
                } else {
                    TerminateOutcome::Failed("PROCESS_TERMINATE_UNCONFIRMED".to_string())
                }
            };
            drop(query);
            outcome
        }
    }
}

#[cfg(not(windows))]
pub fn terminate_owned(_expected: &ProcessIdentity) -> TerminateOutcome {
    TerminateOutcome::Failed("PROCESS_IDENTITY_WINDOWS_ONLY".to_string())
}

/// pipe 客户端进程：PID 由 Windows 从连接给出，程序路径再从该进程句柄读。
#[cfg(windows)]
pub fn pipe_client_process(pipe: *mut std::ffi::c_void) -> Option<PeerProcess> {
    let mut pid = 0u32;
    if unsafe { win::GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
        return None;
    }
    let image_path = identify_process(pid).ok().flatten().map(|identity| identity.image_path);
    Some(PeerProcess { pid, image_path })
}

#[cfg(not(windows))]
pub fn pipe_client_process(_pipe: *mut std::ffi::c_void) -> Option<PeerProcess> {
    None
}

pub struct RunningProgramProbe;

impl ProcessProbe for RunningProgramProbe {
    fn running(&self, paths: &[String]) -> Result<Vec<String>, ServiceError> {
        let shell = system32("WindowsPowerShell").join("v1.0").join("powershell.exe");
        let output = Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", "Get-Process | ForEach-Object { $_.Path }"])
            .output()
            .map_err(|error| ServiceError::new("PROCESS_PROBE_FAILED", error.to_string()))?;
        if !output.status.success() {
            return Err(ServiceError::new("PROCESS_PROBE_FAILED", "无法列出正在运行的程序"));
        }
        let listed = String::from_utf8_lossy(&output.stdout).to_string();
        let running: Vec<&str> = listed.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
        Ok(paths.iter().filter(|path| running.iter().any(|item| item.eq_ignore_ascii_case(path))).cloned().collect())
    }

    fn identify(&self, pid: u32) -> Result<Option<ProcessIdentity>, ServiceError> {
        identify_process(pid)
    }

    fn terminate(&self, expected: &ProcessIdentity) -> TerminateOutcome {
        terminate_owned(expected)
    }
}
