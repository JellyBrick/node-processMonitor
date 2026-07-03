//! N-API bindings for the WMI process monitor.
//!
//! Exposed surface mirrors the historical ffi-napi DLL so the JS wrapper
//! stays a thin adapter:
//! - `setCallback(fn)` registers the (event, process, pid, filepath) callback
//! - `createEventSink` / `createEventSinkAsync`
//! - `getInstanceEvent` / `getInstanceEventAsync` (creation/deletion flags)
//! - `closeEventSink` / `closeEventSinkAsync`

#![deny(clippy::all)]

mod monitor;

use std::sync::Mutex;
use std::sync::mpsc::{Sender, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Task};
use napi_derive::napi;

use monitor::{Command, ProcessEvent, QueryKind, QueryOptions};

type EventArgs = FnArgs<(&'static str, String, String, String)>;
type EventCallback = ThreadsafeFunction<ProcessEvent, (), EventArgs, Status, false>;

struct ListenerHandle {
    commands: Sender<Command>,
    thread: JoinHandle<()>,
}

static LISTENER: Mutex<Option<ListenerHandle>> = Mutex::new(None);
static CALLBACK: Mutex<Option<EventCallback>> = Mutex::new(None);

/// How long JS-facing calls wait for the listener thread to answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

fn create_sink_inner() -> Result<()> {
    let mut listener = LISTENER.lock().unwrap();

    // Idempotent like the old `isReady` flag; also recover from a dead thread.
    if let Some(handle) = listener.as_ref() {
        if !handle.thread.is_finished() {
            return Ok(());
        }
        listener.take();
    }

    let (command_tx, command_rx) = std::sync::mpsc::channel();
    let (init_tx, init_rx) = sync_channel(1);

    let thread = std::thread::Builder::new()
        .name("wql-process-monitor".into())
        .spawn(move || {
            monitor::run(init_tx, command_rx, |event| {
                if let Some(callback) = CALLBACK.lock().unwrap().as_ref() {
                    callback.call(event, ThreadsafeFunctionCallMode::NonBlocking);
                }
            });
        })
        .map_err(|error| to_napi_error(format!("Failed to spawn listener thread: {error}")))?;

    match init_rx.recv_timeout(REPLY_TIMEOUT) {
        Ok(Ok(())) => {
            *listener = Some(ListenerHandle {
                commands: command_tx,
                thread,
            });
            Ok(())
        }
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(to_napi_error(error))
        }
        Err(_) => Err(to_napi_error("Timed out while initializing the event sink")),
    }
}

fn query_inner(options: QueryOptions) -> Result<()> {
    let listener = LISTENER.lock().unwrap();
    let Some(handle) = listener.as_ref() else {
        return Err(to_napi_error("Event sink is not initialized"));
    };

    let (reply_tx, reply_rx) = sync_channel(1);
    handle
        .commands
        .send(Command::Query(options, reply_tx))
        .map_err(|_| to_napi_error("Event sink is not initialized"))?;

    match reply_rx.recv_timeout(REPLY_TIMEOUT) {
        Ok(result) => result.map_err(to_napi_error),
        Err(_) => Err(to_napi_error("Timed out while starting the WQL query")),
    }
}

fn close_inner() {
    let handle = LISTENER.lock().unwrap().take();
    if let Some(handle) = handle {
        let _ = handle.commands.send(Command::Close);
        let _ = handle.thread.join();
    }
}

fn query_options(
    creation: bool,
    deletion: bool,
    filter_windows_noise: bool,
    filter_usual_program_locations: bool,
    whitelist: bool,
    filter: String,
) -> std::result::Result<QueryOptions, String> {
    let kind = match (creation, deletion) {
        (true, true) => QueryKind::Operation,
        (true, false) => QueryKind::Creation,
        (false, true) => QueryKind::Deletion,
        (false, false) => return Err("You must subscribe to at least one event".to_owned()),
    };
    Ok(QueryOptions {
        kind,
        filter_windows_noise,
        filter_usual_program_locations,
        whitelist,
        filter,
    })
}

fn to_napi_error(message: impl ToString) -> Error {
    Error::new(Status::GenericFailure, message.to_string())
}

/// Register the event callback: `(event, process, pid, filepath) => void`.
#[napi]
pub fn set_callback(callback: Function<(), ()>) -> Result<()> {
    let tsfn: EventCallback = callback
        .build_threadsafe_function::<ProcessEvent>()
        .callee_handled::<false>()
        .build_callback(|ctx| {
            let event: ProcessEvent = ctx.value;
            Ok(FnArgs::from((
                event.event,
                event.process,
                event.pid,
                event.filepath,
            )))
        })?;
    *CALLBACK.lock().unwrap() = Some(tsfn);
    Ok(())
}

#[napi]
pub fn create_event_sink() -> Result<()> {
    create_sink_inner()
}

#[napi]
pub fn get_instance_event(
    creation: bool,
    deletion: bool,
    filter_windows_noise: bool,
    filter_usual_program_locations: bool,
    whitelist: bool,
    filter: String,
) -> Result<()> {
    let options = query_options(
        creation,
        deletion,
        filter_windows_noise,
        filter_usual_program_locations,
        whitelist,
        filter,
    )
    .map_err(to_napi_error)?;
    query_inner(options)
}

#[napi]
pub fn close_event_sink() {
    close_inner();
}

pub struct CreateSinkTask;

impl Task for CreateSinkTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        create_sink_inner()
    }

    fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
        Ok(())
    }
}

#[napi(ts_return_type = "Promise<void>")]
pub fn create_event_sink_async() -> AsyncTask<CreateSinkTask> {
    AsyncTask::new(CreateSinkTask)
}

pub struct QueryTask {
    options: Option<QueryOptions>,
    error: Option<String>,
}

impl Task for QueryTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        if let Some(message) = self.error.take() {
            return Err(to_napi_error(message));
        }
        let options = self.options.take().expect("query options consumed twice");
        query_inner(options)
    }

    fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
        Ok(())
    }
}

#[napi(ts_return_type = "Promise<void>")]
pub fn get_instance_event_async(
    creation: bool,
    deletion: bool,
    filter_windows_noise: bool,
    filter_usual_program_locations: bool,
    whitelist: bool,
    filter: String,
) -> AsyncTask<QueryTask> {
    match query_options(
        creation,
        deletion,
        filter_windows_noise,
        filter_usual_program_locations,
        whitelist,
        filter,
    ) {
        Ok(options) => AsyncTask::new(QueryTask {
            options: Some(options),
            error: None,
        }),
        Err(message) => AsyncTask::new(QueryTask {
            options: None,
            error: Some(message),
        }),
    }
}

pub struct CloseSinkTask;

impl Task for CloseSinkTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        close_inner();
        Ok(())
    }

    fn resolve(&mut self, _env: Env, _output: Self::Output) -> Result<Self::JsValue> {
        Ok(())
    }
}

#[napi(ts_return_type = "Promise<void>")]
pub fn close_event_sink_async() -> AsyncTask<CloseSinkTask> {
    AsyncTask::new(CloseSinkTask)
}
