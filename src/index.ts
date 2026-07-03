/*
MIT License

Copyright (c) 2020-2021 Anthony Beaumont

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Emittery from "emittery";

import { Failure } from "./error.js";

export type ProcessMonitorEvents = {
  /**
   * Process creation event
   * `[processName, processId, filepath]`
   */
  creation: [process: string, pid: string, filepath: string];
  /**
   * Process deletion event
   * `[processName, processId]`
   */
  deletion: [process: string, pid: string];
};

export type ProcessMonitorEmitter = Emittery<ProcessMonitorEvents>;

export interface SubscribeOptions {
  /**
   * Subscribe to the creation event
   * @default true
   */
  creation?: boolean;
  /**
   * Subscribe to the deletion event
   * @default true
   */
  deletion?: boolean;
  /**
   * Exclude events originating from System32 and SysWOW64 Windows folder as well as integrated OneDrive FileCoAuth.exe.
   * e.g. cmd.exe, powershell.exe, svchost.exe, RuntimeBroker.exe, and others Windows processes.
   *
   * NB: Using this will prevent you to catch any elevated process event.
   * Unless you are also elevated. This is a permission issue (See #2).
   * You can implement your own filter on top of the event emitter result instead.
   * @default false
   */
  filterWindowsNoise?: boolean;
  /**
   * Exclude events originating from Program Files, Program Files (x86), AppData local and AppData Roaming.
   *
   * NB: Using this will prevent you to catch any elevated process event.
   * Unless you are also elevated. This is a permission issue (See #2).
   * You can implement your own filter on top of the event emitter result instead.
   * @default false
   */
  filterUsualProgramLocations?: boolean;
  /**
   * Custom list of process to exclude.
   * eg: ["firefox.exe","chrome.exe",...]
   *
   * NB: There are limits to the number of AND and OR keywords that can be used in WQL queries. Large numbers of WQL keywords used in a complex query can cause WMI to return the WBEM_E_QUOTA_VIOLATION error code as an HRESULT value. The limit of WQL keywords depends on how complex the query is
   * cf: https://docs.microsoft.com/en-us/windows/win32/wmisdk/querying-with-wql
   * If you have a huge list consider implementing your own filter on top of the event emitter result instead.
   * @default []
   */
  filter?: string[];
  /**
   * Use `filter` option as a whitelist.
   * `filterWindowsNoise` / `filterUsualProgramLocations` can still be used.
   * Previously mentioned limitation(s) still apply.
   *
   * @default false
   */
  whitelist?: boolean;
}

interface NativeAddon {
  setCallback(
    callback: (event: string, process: string, pid: string, filepath: string) => void,
  ): void;
  createEventSink(): void;
  createEventSinkAsync(): Promise<void>;
  closeEventSink(): void;
  closeEventSinkAsync(): Promise<void>;
  getInstanceEvent(
    creation: boolean,
    deletion: boolean,
    filterWindowsNoise: boolean,
    filterUsualProgramLocations: boolean,
    whitelist: boolean,
    filter: string,
  ): void;
  getInstanceEventAsync(
    creation: boolean,
    deletion: boolean,
    filterWindowsNoise: boolean,
    filterUsualProgramLocations: boolean,
    whitelist: boolean,
    filter: string,
  ): Promise<void>;
}

const ARCH: Record<string, string> = {
  x64: "x64",
  ia32: "x86",
  arm64: "arm64",
};

function load(): { lib: NativeAddon; emitter: ProcessMonitorEmitter } {
  const arch = ARCH[process.arch];
  if (!arch) {
    throw new Failure(`Unsupported architecture: ${process.arch}`, "ERR_UNSUPPORTED_ARCH");
  }

  const file = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "lib",
    "dist",
    `processMonitor.${arch}.node`,
  ).replace("app.asar", "app.asar.unpacked"); //electron asar friendly

  const require = createRequire(import.meta.url);
  const lib = require(file) as NativeAddon;

  const emitter: ProcessMonitorEmitter = new Emittery();

  lib.setCallback((event, process, pid, filepath) => {
    if (event === "creation") {
      void emitter.emit("creation", [process, pid, filepath]);
    } else if (event === "deletion") {
      void emitter.emit("deletion", [process, pid]);
    } else {
      throw new Failure(`Unknow event "${event}"`, "ERR_UNEXPECTED_EVENT");
    }
  });

  return { lib, emitter };
}

const shared: ReturnType<typeof load> = ((globalThis as Record<symbol, unknown>)[
  Symbol.for("@jellybrick/wql-process-monitor")
] ??= load()) as ReturnType<typeof load>;

const { lib, emitter } = shared;

interface NormalizedOptions {
  creation: boolean;
  deletion: boolean;
  filterWindowsNoise: boolean;
  filterUsualProgramLocations: boolean;
  whitelist: boolean;
  filter: string[];
}

function normalize(option: SubscribeOptions = {}): NormalizedOptions {
  return {
    filterWindowsNoise: option.filterWindowsNoise || false,
    filterUsualProgramLocations: option.filterUsualProgramLocations || false,
    creation: option.creation != null ? option.creation : true,
    deletion: option.deletion != null ? option.deletion : true,
    filter: option.filter && Array.isArray(option.filter) ? option.filter : [],
    whitelist: option.whitelist || false,
  };
}

function assertSubscribable(options: NormalizedOptions): void {
  if (!options.creation && !options.deletion) {
    throw new Failure("You must subscribe to at least one event", "ERR_INVALID_ARGS");
  }
}

/**
 * Promisified version of wql
 */
export const promises = {
  /**
   * @deprecated Since version >= 2.0 this is automatically done for you when you call subscribe(). Method was merely kept for backward compatibility.
   */
  createEventSink(): Promise<void> {
    return lib.createEventSinkAsync().catch((err: Error) => {
      throw new Failure(err.message, "ERR_EVENTSINK_INIT_FAIL");
    });
  },
  /**
   * Properly close the event sink.
   * There is no 'un-subscribe' thing to do prior to closing the sink. Just close it.
   * It is recommended to properly close the event sink when you are done if you intend to re-open it later on.
   * Most of the time you wouldn't have to bother with this, but it's here in case you need it.
   */
  closeEventSink(): Promise<void> {
    return lib.closeEventSinkAsync();
  },
  /**
   * Subscribe to process creation and deletion events.
   */
  async subscribe(option: SubscribeOptions = {}): Promise<ProcessMonitorEmitter> {
    const options = normalize(option);
    assertSubscribable(options);

    await this.createEventSink();

    await lib
      .getInstanceEventAsync(
        options.creation,
        options.deletion,
        options.filterWindowsNoise,
        options.filterUsualProgramLocations,
        options.whitelist,
        options.filter.toString(),
      )
      .catch((err: Error) => {
        throw new Failure(err.message || "Unknown error", "ERR_WQL_QUERY_FAIL");
      });

    return emitter;
  },
};

/**
 * @deprecated Since version >= 2.0 this is automatically done for you when you call subscribe(). Method was merely kept for backward compatibility.
 */
export function createEventSink(): void {
  try {
    lib.createEventSink();
  } catch (err) {
    throw new Failure((err as Error).message, "ERR_EVENTSINK_INIT_FAIL");
  }
}

/**
 * Properly close the event sink.
 * There is no 'un-subscribe' thing to do prior to closing the sink. Just close it.
 * It is recommended to properly close the event sink when you are done if you intend to re-open it later on.
 * Most of the time you wouldn't have to bother with this, but it's here in case you need it.
 */
export function closeEventSink(): void {
  lib.closeEventSink();
}

/**
 * Subscribe to process creation and deletion events.
 *
 * Usage of promise instead of sync is recommended so that you will not block Node's event loop.
 */
export function subscribe(option: SubscribeOptions = {}): ProcessMonitorEmitter {
  const options = normalize(option);
  assertSubscribable(options);

  createEventSink();

  try {
    lib.getInstanceEvent(
      options.creation,
      options.deletion,
      options.filterWindowsNoise,
      options.filterUsualProgramLocations,
      options.whitelist,
      options.filter.toString(),
    );
  } catch (err) {
    throw new Failure((err as Error).message || "Unknown error", "ERR_WQL_QUERY_FAIL");
  }

  return emitter;
}

export { Failure };
