#!/usr/bin/env node

import { runCli } from "../src/cli.js";
import { terminalText } from "../src/core/ui.js";

function tolerateClosedPipe(error) {
  if (error?.code === "EPIPE") return;
  throw error;
}

// Node ignores SIGPIPE. Treat a downstream reader closing stdout/stderr as a
// normal pipe lifecycle instead of crashing midway through report generation.
process.stdout.on("error", tolerateClosedPipe);
process.stderr.on("error", tolerateClosedPipe);

const interruptController = new AbortController();
const onSigint = () => requestInterrupt("SIGINT");
const onSigterm = () => requestInterrupt("SIGTERM");

function requestInterrupt(signal) {
  const exitCode = signal === "SIGTERM" ? 143 : 130;
  if (interruptController.signal.aborted) {
    process.exit(exitCode);
  }
  process.exitCode = exitCode;
  interruptController.abort({ signal });
}

process.once("SIGINT", onSigint);
process.once("SIGTERM", onSigterm);

runCli(process.argv.slice(2), { signal: interruptController.signal }).catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`\nModular could not complete the scan: ${terminalText(message)}\n`);
  if (process.env.MODULAR_DEBUG && error instanceof Error && error.stack) {
    process.stderr.write(`${error.stack}\n`);
  }
  process.exitCode = 1;
}).finally(() => {
  process.removeListener("SIGINT", onSigint);
  process.removeListener("SIGTERM", onSigterm);
});
