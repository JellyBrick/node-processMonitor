//! WMI process event listener.
//!
//! A dedicated thread owns every COM object (MTA). Commands come in over a
//! channel; events go out through a caller-provided sink callback.
//!
//! Unlike the previous C++ implementation this uses a semisynchronous
//! `ExecNotificationQuery` (polled with a timeout) instead of an asynchronous
//! `IWbemObjectSink` + `IUnsecuredApartment`. No COM calls ever enter this
//! process from outside, so process-wide COM security settings (which hosts
//! like Chromium/Electron >= 43 configure before any JS runs) cannot break
//! event delivery.

use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, RPC_E_CHANGED_MODE, RPC_E_TOO_LATE};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::System::Variant::{
    VARIANT, VT_BSTR, VT_EMPTY, VT_NULL, VT_UNKNOWN, VariantClear,
};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_GENERIC_FLAG_TYPE, WbemLocator,
};
use windows::core::{BSTR, Interface, PCWSTR, w};

/// Messages are kept identical to the historical `ErrorCode` table of the
/// ffi implementation so the JS wrapper surfaces the exact same strings.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "COM library for the calling thread already initialized with different threading model. Please use 'COINIT_MULTITHREADED'"
    )]
    ComChangedMode,
    #[error("Failed to initialize COM library for the calling thread")]
    ComInit,
    #[error("Failed to initialize security")]
    ComSecurity,
    #[error("Failed to create IWbemLocator object")]
    WbemLocator,
    #[error("Could not connect to ROOT\\CIMV2 WMI namespace")]
    WbemConnect,
    #[error("Could not set proxy blanket")]
    ProxyBlanket,
    #[error("{0}")]
    Query(String),
}

/// How long a single semisynchronous `Next` call may block before we check
/// the command channel again.
const POLL_TIMEOUT_MS: i32 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    Creation,
    Deletion,
    Operation,
}

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub kind: QueryKind,
    pub filter_windows_noise: bool,
    pub filter_usual_program_locations: bool,
    pub whitelist: bool,
    /// Comma separated process names (historical CSV convention of the ffi API).
    pub filter: String,
}

#[derive(Debug)]
pub struct ProcessEvent {
    /// "creation" | "deletion"
    pub event: &'static str,
    pub process: String,
    /// Pid as a string (WMI `Handle` property), matching the previous API.
    pub pid: String,
    /// Full image path. Only resolved for creation events, may be empty.
    pub filepath: String,
}

pub enum Command {
    /// Start (or replace) the notification query.
    Query(QueryOptions, SyncSender<Result<(), Error>>),
    /// Stop everything and exit the listener thread.
    Close,
}

// Same clauses as the C++ implementation.
const FILTER_WINDOWS_NOISE: &str = " AND NOT TargetInstance.ExecutablePath LIKE '%Windows\\\\System32%'\
     AND NOT TargetInstance.ExecutablePath LIKE '%Windows\\\\SysWOW64%'\
     AND TargetInstance.Name != 'FileCoAuth.exe'"; //OneDrive

const FILTER_USUAL_PROGRAM_LOCATIONS: &str = " AND NOT TargetInstance.ExecutablePath LIKE '%Program Files%'\
     AND NOT TargetInstance.ExecutablePath LIKE '%Program Files (x86)%'\
     AND NOT TargetInstance.ExecutablePath LIKE '%AppData\\\\Local%'\
     AND NOT TargetInstance.ExecutablePath LIKE '%AppData\\\\Roaming%'";

fn build_query(options: &QueryOptions) -> String {
    let source = match options.kind {
        QueryKind::Creation => "__InstanceCreationEvent",
        QueryKind::Deletion => "__InstanceDeletionEvent",
        QueryKind::Operation => "__InstanceOperationEvent",
    };

    let mut query = String::with_capacity(768 + options.filter.len() * 2);
    query.push_str("SELECT * FROM ");
    query.push_str(source);
    query.push_str(" WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

    if options.filter_windows_noise {
        query.push_str(FILTER_WINDOWS_NOISE);
    }
    if options.filter_usual_program_locations {
        query.push_str(FILTER_USUAL_PROGRAM_LOCATIONS);
    }

    if !options.filter.is_empty() {
        // Historical behavior: plain CSV split, no trimming, no escaping.
        if options.whitelist {
            for (i, name) in options.filter.split(',').enumerate() {
                query.push_str(if i == 0 {
                    " AND ( TargetInstance.Name = '"
                } else {
                    " OR TargetInstance.Name = '"
                });
                query.push_str(name);
                query.push('\'');
            }
            query.push_str(" )");
        } else {
            for name in options.filter.split(',') {
                query.push_str(" AND TargetInstance.Name != '");
                query.push_str(name);
                query.push('\'');
            }
        }
    }

    query
}

/// Owned VARIANT that is cleared on drop (the raw binding has no Drop impl).
struct Variant(VARIANT);

impl Drop for Variant {
    fn drop(&mut self) {
        unsafe {
            let _ = VariantClear(&mut self.0);
        }
    }
}

/// Per-thread COM initialization, balanced by `CoUninitialize` on drop.
struct ComGuard;

impl ComGuard {
    fn init() -> Result<Self, Error> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() {
            return Err(if hr == RPC_E_CHANGED_MODE {
                Error::ComChangedMode
            } else {
                Error::ComInit
            });
        }
        Ok(Self)
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

struct Connection {
    // Field order matters: `services` must be released before `_com` runs
    // CoUninitialize.
    services: IWbemServices,
    _com: ComGuard,
}

fn connect() -> Result<Connection, Error> {
    let com = ComGuard::init()?;

    unsafe {
        // Process-wide COM security. RPC_E_TOO_LATE means the host
        // (e.g. Chromium/Electron >= 43) already configured it before us,
        // which is fine: we set per-proxy security below anyway.
        if let Err(error) = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        ) && error.code() != RPC_E_TOO_LATE
        {
            return Err(Error::ComSecurity);
        }

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|_| Error::WbemLocator)?;

        let services = locator
            .ConnectServer(
                &BSTR::from("ROOT\\CIMV2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|_| Error::WbemConnect)?;

        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .map_err(|_| Error::ProxyBlanket)?;

        Ok(Connection {
            services,
            _com: com,
        })
    }
}

fn start_query(
    connection: &Connection,
    options: &QueryOptions,
) -> Result<IEnumWbemClassObject, Error> {
    let query = build_query(options);
    unsafe {
        let enumerator = connection
            .services
            .ExecNotificationQuery(
                &BSTR::from("WQL"),
                &BSTR::from(query.as_str()),
                WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_RETURN_IMMEDIATELY.0 | WBEM_FLAG_FORWARD_ONLY.0),
                None,
            )
            .map_err(|error| Error::Query(error.message().to_string()))?;

        // The enumerator is its own proxy and needs its own blanket.
        CoSetProxyBlanket(
            &enumerator,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .map_err(|error| Error::Query(error.message().to_string()))?;

        Ok(enumerator)
    }
}

/// Read a string property from a WMI object, reproducing the quirky
/// NULL/EMPTY placeholders of the previous implementation.
fn prop_string(object: &IWbemClassObject, name: PCWSTR) -> String {
    let mut value = Variant(VARIANT::default());
    if unsafe { object.Get(name, 0, &mut value.0, None, None) }.is_err() {
        return String::new();
    }

    let inner = unsafe { &value.0.Anonymous.Anonymous };
    if inner.vt == VT_NULL {
        "NULL".to_owned()
    } else if inner.vt == VT_EMPTY {
        "EMPTY".to_owned()
    } else if inner.vt == VT_BSTR {
        unsafe { inner.Anonymous.bstrVal.to_string() }
    } else {
        String::new()
    }
}

/// Full image path of a live process, empty string when unavailable
/// (access denied, process already gone, ...).
fn process_image_path(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return String::new();
        };
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let path = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .map(|_| String::from_utf16_lossy(&buffer[..size as usize]))
        .unwrap_or_default();
        let _ = CloseHandle(handle);
        path
    }
}

fn extract_event(object: &IWbemClassObject) -> Option<ProcessEvent> {
    let class = prop_string(object, w!("__CLASS"));
    let event = match class.as_str() {
        "__InstanceCreationEvent" => "creation",
        "__InstanceDeletionEvent" => "deletion",
        // __InstanceModificationEvent and anything else: ignored, as before.
        _ => return None,
    };

    // TargetInstance is a VT_UNKNOWN variant holding the Win32_Process object.
    let mut value = Variant(VARIANT::default());
    unsafe { object.Get(w!("TargetInstance"), 0, &mut value.0, None, None) }.ok()?;
    let inner = unsafe { &value.0.Anonymous.Anonymous };
    if inner.vt != VT_UNKNOWN {
        return None;
    }
    let unknown = (unsafe { &*inner.Anonymous.punkVal }).as_ref()?;
    let target = unknown.cast::<IWbemClassObject>().ok()?;

    let process = prop_string(&target, w!("Name"));
    let pid = prop_string(&target, w!("Handle"));
    let filepath = if event == "creation" {
        process_image_path(pid.parse().unwrap_or(0))
    } else {
        String::new()
    };

    Some(ProcessEvent {
        event,
        process,
        pid,
        filepath,
    })
}

/// Body of the listener thread. `init_reply` reports the connection outcome
/// back to `createEventSink`.
pub fn run(
    init_reply: SyncSender<Result<(), Error>>,
    commands: Receiver<Command>,
    sink: impl Fn(ProcessEvent),
) {
    let connection = match connect() {
        Ok(connection) => {
            let _ = init_reply.send(Ok(()));
            connection
        }
        Err(error) => {
            let _ = init_reply.send(Err(error));
            return;
        }
    };

    // Only one active notification query at a time: a new Query replaces the
    // previous one (the old ffi implementation piled queries onto one sink,
    // duplicating events - there is no sane use case for that).
    let mut enumerator: Option<IEnumWbemClassObject> = None;

    loop {
        // With an active query, peek at the channel between polls; when idle,
        // block until a command arrives.
        let command = if enumerator.is_some() {
            match commands.try_recv() {
                Ok(command) => Some(command),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => break,
            }
        } else {
            match commands.recv_timeout(Duration::from_secs(3600)) {
                Ok(command) => Some(command),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        };

        if let Some(command) = command {
            match command {
                Command::Query(options, reply) => {
                    match start_query(&connection, &options) {
                        Ok(new_enumerator) => {
                            enumerator = Some(new_enumerator);
                            let _ = reply.send(Ok(()));
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                    continue;
                }
                Command::Close => break,
            }
        }

        if let Some(active) = &enumerator {
            // Semisynchronous poll; WBEM_S_TIMEDOUT simply means "no event yet".
            let mut objects: [Option<IWbemClassObject>; 16] = Default::default();
            let mut returned = 0u32;
            let hr = unsafe { active.Next(POLL_TIMEOUT_MS, &mut objects, &mut returned) };
            if hr.is_err() {
                // Enumerator died (WMI restart, ...): drop it, keep serving
                // commands so a caller can subscribe again.
                enumerator = None;
                continue;
            }
            for object in objects.iter_mut().take(returned as usize) {
                if let Some(object) = object.take()
                    && let Some(event) = extract_event(&object)
                {
                    sink(event);
                }
            }
        }
    }
    // RAII order: enumerator and Connection.services release their proxies,
    // then ComGuard runs CoUninitialize.
}
