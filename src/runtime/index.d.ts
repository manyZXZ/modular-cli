import type {
  RuleDescriptor,
  RuntimeAuditInput,
  RuntimeAuditResult,
  RuntimeStaticServer,
  RuntimeStaticServerOptions,
  RuntimeViewport,
  RuntimeViewportPreset,
} from "../index.js";

export const MAX_RUNTIME_ROUTES: 25;
export const RUNTIME_VIEWPORTS: Readonly<Record<RuntimeViewportPreset, RuntimeViewport>>;
export const RUNTIME_AUDIT_DEFAULTS: Readonly<{
  maxRoutes: number;
  totalTimeoutMs: number;
  launchTimeoutMs: number;
  navigationTimeoutMs: number;
  loadTimeoutMs: number;
  stabilizationMs: number;
  measurementTimeoutMs: number;
  accessibilityTimeoutMs: number;
  cleanupTimeoutMs: number;
  browserName: "chromium" | "firefox" | "webkit";
  viewportPreset: RuntimeViewportPreset;
}>;
export const RUNTIME_RULE_FAMILIES: readonly RuleDescriptor[];

export class RuntimeAuditError extends Error {
  code: string;
  stage: string | null;
  timedOut: boolean;
  constructor(code: string, message: string, options?: ErrorOptions & { stage?: string | null; timedOut?: boolean });
}

export class RuntimeStaticServerError extends Error {
  code: string;
  constructor(code: string, message: string, options?: ErrorOptions);
}

export function discoverRuntimeCapabilities(options?: {
  root?: string;
  includeModuleFallback?: boolean;
  importer?: (...args: unknown[]) => unknown | Promise<unknown>;
}): Promise<Record<string, unknown>>;
export function isLoopbackHostname(hostname: string): boolean;
export function isRuntimeNetworkUrlAllowed(value: string | URL, options?: { allowRemote?: boolean }): boolean;
export function runRuntimeBrowserAudit(input?: RuntimeAuditInput): Promise<RuntimeAuditResult>;
export function startRuntimeStaticServer(options?: RuntimeStaticServerOptions): Promise<RuntimeStaticServer>;
