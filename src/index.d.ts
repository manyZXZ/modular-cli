export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Threshold = Severity | "none";
export type Confidence = "high" | "medium" | "low";
export type ScanMode = "security" | "mysite";
export type MachineFormat = "json" | "sarif";
export type BrowserName = "chromium" | "firefox" | "webkit";
export type RuntimeViewportPreset = "mobile" | "desktop";

export interface FindingStandard {
  id: string;
  title?: string;
  url?: string;
}

export interface FindingSuppression {
  status: "accepted";
  reason: string;
  expires?: string;
  rule?: string;
  path?: string;
}

export interface FindingInput {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence?: Confidence;
  description?: string;
  recommendation?: string;
  action?: string;
  evidence?: string;
  file?: string | null;
  line?: number | null;
  suggestedFiles?: string[];
  tags?: string[];
  standards?: FindingStandard[];
  references?: string[];
  manual?: boolean;
  ruleFamily?: string;
  scoreFamily?: string;
  fingerprint?: string;
  baselineState?: "new" | "unchanged";
  baselineChange?: "severity-increased";
  previousSeverity?: Severity;
  detailOmitted?: boolean;
  suppression?: FindingSuppression;
  [key: string]: unknown;
}

export interface Finding extends FindingInput {
  confidence: Confidence;
  description: string;
  recommendation: string;
  evidence: string;
  file: string | null;
  line: number | null;
  suggestedFiles: string[];
  tags: string[];
  standards: FindingStandard[];
  references: string[];
  manual: boolean;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RiskContribution {
  id: string;
  signalId: string;
  severity: Severity;
  confidence: string;
  validation: "automated" | "manual";
  points: number;
}

export interface FindingSummary {
  counts: SeverityCounts;
  score: number;
  total: number;
  risk: {
    model: "rule-family-confidence-v2";
    riskScore: number;
    band: string;
    rawPoints: number;
    scoredRuleFamilies: number;
    signaledRuleFamilies: number;
    repeatedSignalsExcluded: number;
    automatedSignals: number;
    manualReviewItems: number;
    contributions: RiskContribution[];
    explanation: string;
    formula: string;
    parameters: Record<string, unknown>;
  };
}

export type RuleStatus =
  | "completed"
  | "applicable"
  | "partial"
  | "not-applicable"
  | "not_applicable"
  | "skipped"
  | "disabled"
  | "unavailable"
  | "unknown";

export interface RuleDescriptor {
  id: string;
  kind?: "automated" | "manual";
  status?: RuleStatus | string;
  [key: string]: unknown;
}

export interface RuleFamilyAssessment {
  terminology: string;
  ruleFamilies: {
    configured: number;
    described: number;
    automated: number;
    manual: number;
    unclassified: number;
    applicable: number;
    notApplicable: number;
    skipped: number;
    applicabilityUnknown: number;
    optionalChecksSkipped: number;
  };
  findingSignals: { automated: number; manualReview: number };
}

export interface ScanResult<Mode extends string = ScanMode> {
  schemaVersion: 1;
  mode: Mode;
  title: string;
  root: string;
  generatedAt: string;
  durationMs: number;
  filesScanned: number;
  checks: number;
  findings: Finding[];
  summary: FindingSummary;
  metadata: Record<string, unknown> & { assessment?: RuleFamilyAssessment };
  [key: string]: unknown;
}

export interface BuildScanResultInput<Mode extends string = ScanMode> {
  mode: Mode;
  title: string;
  root: string;
  findings: FindingInput[];
  checks: number;
  filesScanned: number;
  startedAt?: number;
  metadata?: Record<string, unknown>;
}

export interface FileIdentity {
  dev: string;
  ino: string;
  size: number;
  mtimeNs: string;
  ctimeNs: string;
}

export interface FileDescriptor {
  absolute: string;
  relative: string;
  name: string;
  extension: string;
  size?: number;
  identity?: FileIdentity;
  digest?: string;
  maxFileBytes: number;
  contentReadable?: boolean;
  skippedReason?: "binary" | "large" | "link" | "inaccessible" | string;
  assetMetadata?: boolean;
}

export interface VerifiedFileMetadata {
  readonly absolute: string;
  readonly relative: string;
  readonly extension: string;
  readonly size: number;
}

export interface SkippedFileCounts {
  binary: number;
  assetMetadata: number;
  large: number;
  inaccessible: number;
  links: number;
  limit: number;
  totalBytes: number;
  [key: string]: number;
}

export interface CollectFilesOptions {
  maxFileBytes?: number;
  maxFiles?: number;
  maxTotalBytes?: number;
  ignore?: string[];
  excludeDirectories?: string[];
}

export interface FileCollection {
  files: FileDescriptor[];
  skipped: SkippedFileCounts;
  totalReadableBytes: number;
  maxTotalBytes: number;
}

export interface ScannerProgress {
  stage?: string;
  current: number;
  total: number;
  file?: string;
  [key: string]: unknown;
}

export interface ScannerInput {
  root?: string;
  files?: FileDescriptor[];
  skipped?: Partial<SkippedFileCounts>;
  onProgress?: (progress: ScannerProgress) => void | Promise<void>;
  options?: Record<string, unknown>;
}

export interface ScanModuleDefinition {
  id: string;
  version: number;
  title: string;
  description: string;
  runnerKey: string;
  capabilities?: Partial<Record<"website" | "runtime" | "dependencyAudit", boolean>>;
  reports: readonly { file: string; title: string }[];
  load: () => Promise<(input?: ScannerInput) => Promise<ScanResult<string>>>;
}

export interface ScanModule extends Omit<ScanModuleDefinition, "capabilities" | "reports"> {
  readonly capabilities: Readonly<Record<"website" | "runtime" | "dependencyAudit", boolean>>;
  readonly reports: readonly Readonly<{ file: string; title: string }>[];
}

export const SCAN_MODULES: readonly Readonly<ScanModule>[];
export function createScanModuleRegistry(definitions: readonly ScanModuleDefinition[]): readonly Readonly<ScanModule>[];
export function getScanModule(id: string): Readonly<ScanModule>;

export interface WebProjectDetection {
  isWebsite: boolean;
  confidence: number;
  signals: string[];
  reasons: string[];
  framework: string | null;
}

export interface SuppressionPolicy {
  rule: string;
  path?: string;
  reason: string;
  expires?: string;
}

export interface ProjectConfiguration {
  $schema?: string;
  failOn?: Threshold;
  failOnNew?: Threshold;
  failOnRegression?: Threshold;
  failOnIncomplete?: boolean;
  baseline?: string;
  ignore?: string[];
  maxFindingsPerRule?: number;
  outputFormats?: MachineFormat[];
  suppressions?: SuppressionPolicy[];
}

export interface BaselineEntry {
  mode: ScanMode;
  fingerprint: string;
  ruleId: string;
  severity: string;
  file: string | null;
  title: string;
}

export interface BaselineDocument {
  schemaVersion: 1;
  kind: "modular-baseline";
  tool: { name: "Modular"; version: string };
  generatedAt: string | null;
  modes: ScanMode[];
  entries: BaselineEntry[];
}

export interface LoadedBaseline extends BaselineDocument {
  keys: Set<string>;
  path?: string;
}

export interface RuntimeViewport {
  readonly width: number;
  readonly height: number;
}

export interface RuntimeAuditInput {
  enabled?: boolean;
  root?: string;
  url?: string;
  routes?: string[];
  allowRemote?: boolean;
  auditSecurityHeaders?: boolean;
  browserName?: BrowserName;
  browserChannel?: string | null;
  viewportPreset?: RuntimeViewportPreset;
  maxRoutes?: number;
  totalTimeoutMs?: number;
  launchTimeoutMs?: number;
  navigationTimeoutMs?: number;
  loadTimeoutMs?: number;
  stabilizationMs?: number;
  measurementTimeoutMs?: number;
  accessibilityTimeoutMs?: number;
  cleanupTimeoutMs?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ScannerProgress) => void | Promise<void>;
  adapters?: Record<string, unknown>;
  includeModuleFallback?: boolean;
}

export interface RuntimeAuditResult extends ScanResult<"runtime"> {
  status: "disabled" | "completed" | "partial" | "unavailable" | "failed" | string;
  url: string | null;
  capabilities: Record<string, unknown>;
  stages: Record<string, unknown>;
  limits?: Record<string, number> | null;
  viewport?: { preset: RuntimeViewportPreset; width: number; height: number };
  checkDescriptors: RuleDescriptor[];
  metrics: Record<string, unknown>;
  policy: Record<string, unknown>;
}

export interface RuntimeStaticServerOptions {
  enabled?: boolean;
  root?: string;
  directory?: string;
  host?: "127.0.0.1" | "::1";
  port?: number;
  spaFallback?: boolean;
  startupTimeoutMs?: number;
  closeTimeoutMs?: number;
  requestTimeoutMs?: number;
}

export interface RuntimeStaticServer {
  readonly url: string;
  readonly host: string;
  readonly port: number;
  readonly root: string;
  readonly repositoryRoot: string;
  readonly spaFallback: boolean;
  readonly repositoryScriptsExecuted: false;
  close(): Promise<void>;
}

export interface CliOptions {
  help?: true;
  version?: true;
  command?: "check" | "doctor";
  mode?: ScanMode | "all" | "doctor";
  root?: string;
  output?: string | null;
  color?: boolean;
  quiet?: boolean;
  failOn?: Threshold;
  failOnNew?: Threshold;
  failOnRegression?: Threshold;
  failOnIncomplete?: boolean;
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  maxFindingsPerRule?: number | null;
  ignore?: string[];
  config?: string | null;
  configDisabled?: boolean;
  baseline?: string | null;
  writeBaseline?: string | null;
  suppressions?: SuppressionPolicy[];
  machineFormats?: MachineFormat[];
  auditDependencies?: boolean;
  runtimeAudit?: boolean;
  runtimeUrl?: string | null;
  runtimeStaticDir?: string | null;
  runtimeRoutes?: string[];
  runtimeAllowRemote?: boolean;
  runtimeBrowser?: BrowserName;
  runtimeBrowserChannel?: string | null;
  runtimeViewport?: RuntimeViewportPreset;
  runtimeMaxRoutes?: number;
  runtimeTimeoutMs?: number;
  runtimeSpaFallback?: boolean;
  [key: string]: unknown;
}

export interface CliRuntime {
  stdout?: { write(chunk: string): unknown };
  stderr?: { write(chunk: string): unknown };
  signal?: AbortSignal;
  setExitCode?: (code: number) => void;
  [key: string]: unknown;
}

export const EXIT: Readonly<{ ok: 0; usage: 2; threshold: 3; failed: 1; sigint: 130; sigterm: 143 }>;
export class CliError extends Error { exitCode: number; constructor(message: string, code?: number); }
export function parseCliArguments(argv: readonly string[]): CliOptions;
export function runCli(argv: readonly string[], runtime?: CliRuntime): Promise<number>;
export function shouldFail(result: ScanResult<string>, threshold: Threshold): boolean;
export function usage(): string;

export const DEFAULT_IGNORED_DIRECTORIES: ReadonlySet<string>;
export const WEB_ASSET_EXTENSIONS: ReadonlySet<string>;
export function collectFiles(root: string, options?: CollectFilesOptions): Promise<FileCollection>;
export function isWebAssetFile(file: Partial<FileDescriptor>): boolean;
export function verifyFileMetadata(file: Partial<FileDescriptor>, options: { root: string }): Promise<VerifiedFileMetadata | null>;
export function detectWebProject(input?: { root?: string; files?: FileDescriptor[] }): Promise<WebProjectDetection>;

export const DEFAULT_CONFIG_FILE: ".modular.json";
export function validateProjectConfiguration(value: unknown, root: string): ProjectConfiguration;
export function loadProjectConfiguration(options?: { root?: string; file?: string | null; disabled?: boolean }): Promise<{ path: string; config: ProjectConfiguration } | null>;

export const MACHINE_REPORT_FILES: Readonly<{ json: "modular-results.json"; sarif: "modular-results.sarif" }>;
export const MACHINE_REPORT_LOCK_FILE: ".modular-machine-report.lock";
export function stableJson(value: unknown): string;
export function createJsonReport(results: ScanResult<string>[], options?: { toolVersion?: string; complete?: boolean; expectedModes?: string[] | null }): Record<string, unknown>;
export function createSarifReport(results: ScanResult<string>[], options?: { toolVersion?: string; complete?: boolean; expectedModes?: string[] | null }): Record<string, unknown>;
export function isOwnedMachineReport(filePath: string, format?: MachineFormat | null): Promise<boolean>;
export function writeMachineReports(results: ScanResult<string>[], options?: {
  outputDirectory?: string;
  formats?: MachineFormat[];
  toolVersion?: string;
  complete?: boolean;
  expectedModes?: string[] | null;
  machineLockTimeoutMs?: number;
  machineLockStaleMs?: number;
}): Promise<string[]>;

export const BASELINE_KIND: "modular-baseline";
export const BASELINE_SCHEMA_VERSION: 1;
export function findingFingerprint(mode: string, finding: FindingInput): string;
export function fingerprintFindings(mode: string, findings: FindingInput[]): string[];
export function loadBaseline(filePath: string, options?: { root?: string | null }): Promise<LoadedBaseline>;
export function applyFindingPolicy<Mode extends string>(result: ScanResult<Mode>, options?: { baseline?: LoadedBaseline | null; suppressions?: SuppressionPolicy[]; now?: Date }): ScanResult<Mode>;
export function findingsAtOrAbove(result: ScanResult<string>, threshold: Threshold, options?: { newOnly?: boolean; regressionsOnly?: boolean }): Finding[];
export function createBaselineDocument(results: ScanResult[], options?: { previous?: BaselineDocument | null; toolVersion?: string; generatedAt?: string }): BaselineDocument;
export function writeBaseline(filePath: string, results: ScanResult[], options?: {
  root?: string;
  previous?: BaselineDocument | null;
  toolVersion?: string;
  generatedAt?: string;
  baselineLockTimeoutMs?: number;
  baselineLockStaleMs?: number;
}): Promise<string>;

export const SEVERITIES: readonly Severity[];
export const SEVERITY_WEIGHT: Readonly<Record<Severity, number>>;
export function createFinding(input: FindingInput): Finding;
export function findingKey(finding: FindingInput): string;
export function deduplicateFindings<T extends FindingInput>(findings: T[]): T[];
export function summarizeFindings(findings: FindingInput[]): FindingSummary;
export function summarizeRuleFamilies(checks: number, metadata: Record<string, unknown>, findings: FindingInput[]): RuleFamilyAssessment;
export function sortFindings<T extends FindingInput>(findings: T[]): T[];
export function buildScanResult<Mode extends string = ScanMode>(input: BuildScanResultInput<Mode>): ScanResult<Mode>;

export const REPORT_FILES: Readonly<{
  overview: "00-overview.md";
  security: readonly ["01-security-report.md", "02-security-action-plan.md"];
  mysite: readonly ["03-site-report.md", "04-site-action-plan.md"];
}>;
export function renderActionPlan(result: ScanResult<string>): string;
export function renderDetailedReport(result: ScanResult<string>): string;
export function writeScanReports(result: ScanResult, options?: {
  outputDirectory?: string;
  overviewResults?: ScanResult[];
  reportLockTimeoutMs?: number;
  reportLockStaleMs?: number;
  afterReportCommit?: () => string[] | Promise<string[]>;
}): Promise<string[]>;

export function runSecurityScan(input?: ScannerInput): Promise<ScanResult<"security">>;
export function runSiteScan(input?: ScannerInput): Promise<ScanResult<"mysite">>;

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
  browserName: BrowserName;
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
