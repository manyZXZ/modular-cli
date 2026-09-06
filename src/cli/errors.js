export const EXIT = Object.freeze({ ok: 0, usage: 2, threshold: 3, failed: 1, sigint: 130, sigterm: 143 });

export class CliError extends Error {
  constructor(message, code = EXIT.usage) {
    super(message);
    this.name = "CliError";
    this.exitCode = code;
  }
}

export class CliInterrupt extends Error {
  constructor(signalName) {
    super(`Scan interrupted by ${signalName}.`);
    this.name = "CliInterrupt";
    this.signalName = signalName;
    this.exitCode = signalName === "SIGTERM" ? EXIT.sigterm : EXIT.sigint;
  }
}

export function throwIfInterrupted(signal) {
  if (!signal?.aborted) return;
  const signalName = signal.reason?.signal === "SIGTERM" ? "SIGTERM" : "SIGINT";
  throw new CliInterrupt(signalName);
}

export function setExitCode(code, runtime) {
  if (runtime.setExitCode) runtime.setExitCode(code);
  else process.exitCode = code;
  return code;
}
