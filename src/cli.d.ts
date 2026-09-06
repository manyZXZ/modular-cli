import type { CliOptions, CliRuntime, ScanResult, Threshold } from "./index.js";

export const EXIT: Readonly<{ ok: 0; usage: 2; threshold: 3; failed: 1; sigint: 130; sigterm: 143 }>;
export class CliError extends Error { exitCode: number; constructor(message: string, code?: number); }
export function parseCliArguments(argv: readonly string[]): CliOptions;
export function runCli(argv: readonly string[], runtime?: CliRuntime): Promise<number>;
export function shouldFail(result: ScanResult<string>, threshold: Threshold): boolean;
export function usage(): string;
