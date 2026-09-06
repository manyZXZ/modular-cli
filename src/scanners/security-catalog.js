const OWASP_2025_ROOT = "https://owasp.org/Top10/2025";
const CWE_ROOT = "https://cwe.mitre.org/data/definitions";

function cwe(id, title) {
  return Object.freeze({ id: `CWE-${id}`, title, url: `${CWE_ROOT}/${id}.html` });
}

function owasp(id, slug, title) {
  return Object.freeze({
    id: `OWASP-${id}:2025`,
    title,
    url: `${OWASP_2025_ROOT}/${id}_2025-${slug}/`,
  });
}

const A01 = owasp("A01", "Broken_Access_Control", "Broken Access Control");
const A02 = owasp("A02", "Security_Misconfiguration", "Security Misconfiguration");
const A03 = owasp("A03", "Software_Supply_Chain_Failures", "Software Supply Chain Failures");
const A04 = owasp("A04", "Cryptographic_Failures", "Cryptographic Failures");
const A05 = owasp("A05", "Injection", "Injection");
const A07 = owasp("A07", "Authentication_Failures", "Authentication Failures");
const A08 = owasp("A08", "Software_or_Data_Integrity_Failures", "Software or Data Integrity Failures");
const A09 = owasp("A09", "Security_Logging_and_Alerting_Failures", "Security Logging and Alerting Failures");

function entry(name, category, standards = []) {
  return Object.freeze({
    name,
    category,
    standards: Object.freeze(standards),
    references: Object.freeze([...new Set(standards.map(({ url }) => url).filter(Boolean))]),
  });
}

/**
 * Stable rule-family catalogue. Mappings intentionally stop at CWE and OWASP
 * Top 10 category level: a static signal is not proof that an ASVS requirement
 * has passed or failed.
 */
export const SECURITY_RULE_CATALOG = Object.freeze({
  "embedded-secrets": entry("Embedded credentials and private keys", "Secrets", [
    cwe(798, "Use of Hard-coded Credentials"), A02, A07,
  ]),
  "public-env-secrets": entry("Secrets exposed through client environment variables", "Secrets", [
    cwe(200, "Exposure of Sensitive Information to an Unauthorized Actor"), A01,
  ]),
  "environment-hygiene": entry("Environment file version-control hygiene", "Secrets", [
    cwe(540, "Inclusion of Sensitive Information in Source Code"), A01, A02,
  ]),
  "dom-xss": entry("DOM injection and unsafe HTML sinks", "Application Security", [
    cwe(79, "Improper Neutralization of Input During Web Page Generation"), A05,
  ]),
  "dynamic-code": entry("Dynamic code execution", "Application Security", [
    cwe(95, "Improper Neutralization of Directives in Dynamically Evaluated Code"), A05,
  ]),
  "server-command-injection": entry("Server-side command injection data flow", "Application Security", [
    cwe(78, "Improper Neutralization of Special Elements used in an OS Command"), A05,
  ]),
  "server-sql-injection": entry("Server-side SQL injection data flow", "Application Security", [
    cwe(89, "Improper Neutralization of Special Elements used in an SQL Command"), A05,
  ]),
  "server-path-traversal": entry("Untrusted file-path data flow", "Application Security", [
    cwe(22, "Improper Limitation of a Pathname to a Restricted Directory"), A01,
  ]),
  "server-ssrf": entry("Server-side request forgery data flow", "Application Security", [
    cwe(918, "Server-Side Request Forgery"), A01,
  ]),
  "insecure-transport": entry("Insecure HTTP, WebSocket and TLS configuration", "Transport Security", [
    cwe(319, "Cleartext Transmission of Sensitive Information"),
    cwe(295, "Improper Certificate Validation"),
    A04,
  ]),
  "browser-storage": entry("Sensitive browser storage", "Authentication", [
    cwe(922, "Insecure Storage of Sensitive Information"), A01, A07,
  ]),
  "weak-cryptography": entry("Weak hashes and security-sensitive randomness", "Cryptography", [
    cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"),
    cwe(338, "Use of Cryptographically Weak Pseudo-Random Number Generator"),
    A04,
  ]),
  "cross-window-messaging": entry("postMessage target and origin validation", "Browser Security", [
    cwe(346, "Origin Validation Error"), A07,
  ]),
  "external-navigation": entry("Reverse tabnabbing and unsafe URL schemes", "Browser Security", [
    cwe(1022, "Use of Web Link to Untrusted Target with window.opener Access"), A01,
  ]),
  "untrusted-navigation": entry("User-controlled redirects and popup destinations", "Browser Security", [
    cwe(601, "URL Redirection to Untrusted Site"), A01,
  ]),
  "embedded-content": entry("Third-party iframe and srcdoc isolation", "Browser Security", [
    cwe(1021, "Improper Restriction of Rendered UI Layers or Frames"), A02,
  ]),
  cors: entry("Permissive cross-origin policy", "Security Configuration", [
    cwe(942, "Permissive Cross-domain Policy with Untrusted Domains"), A02,
  ]),
  "hardcoded-auth": entry("Hardcoded authorization material", "Authentication", [
    cwe(798, "Use of Hard-coded Credentials"), A02, A07,
  ]),
  "cookie-flags": entry("Authentication cookie flags", "Authentication", [
    cwe(1004, "Sensitive Cookie Without HttpOnly Flag"),
    cwe(614, "Sensitive Cookie in HTTPS Session Without Secure Attribute"),
    cwe(1275, "Sensitive Cookie with Improper SameSite Attribute"),
    A01, A02,
  ]),
  "jwt-validation": entry("JWT signature and claim validation", "Authentication", [
    cwe(347, "Improper Verification of Cryptographic Signature"), A04, A07,
  ]),
  "dependency-hygiene": entry("Dependency source and version hygiene", "Supply Chain", [
    cwe(829, "Inclusion of Functionality from Untrusted Control Sphere"), A03,
  ]),
  "dependency-advisories": entry("Installed dependency advisories", "Supply Chain", [
    cwe(1104, "Use of Unmaintained Third Party Components"), A03,
  ]),
  "dependency-advisory": entry("Installed dependency advisories", "Supply Chain", [
    cwe(1104, "Use of Unmaintained Third Party Components"), A03,
  ]),
  "dependency-audit-unavailable": entry("Dependency advisory audit availability", "Supply Chain", [A03]),
  "package-scripts": entry("Package lifecycle and install scripts", "Supply Chain", [
    cwe(494, "Download of Code Without Integrity Check"), A03, A08,
  ]),
  lockfile: entry("Reproducible dependency lockfile", "Supply Chain", [A03]),
  "lockfile-integrity": entry("Lockfile transport and integrity metadata", "Supply Chain", [
    cwe(353, "Missing Support for Integrity Check"), A03, A08,
  ]),
  "ci-workflow": entry("CI workflow trust boundaries", "Supply Chain", [
    cwe(78, "Improper Neutralization of Special Elements used in an OS Command"),
    cwe(829, "Inclusion of Functionality from Untrusted Control Sphere"),
    A03, A05,
  ]),
  "container-hardening": entry("Container privilege and build trust boundaries", "Security Configuration", [
    cwe(250, "Execution with Unnecessary Privileges"),
    cwe(494, "Download of Code Without Integrity Check"),
    A02, A03,
  ]),
  "iac-exposure": entry("Infrastructure-as-code public exposure", "Security Configuration", [
    cwe(284, "Improper Access Control"),
    cwe(732, "Incorrect Permission Assignment for Critical Resource"),
    A01, A02,
  ]),
  "security-headers": entry("Browser security headers and CSP", "Security Headers", [
    cwe(693, "Protection Mechanism Failure"), A02,
  ]),
  "source-maps": entry("Production source-map exposure", "Information Exposure", [
    cwe(540, "Inclusion of Sensitive Information in Source Code"), A01, A02,
  ]),
  "sensitive-logging": entry("Sensitive data written to browser logs", "Information Exposure", [
    cwe(532, "Insertion of Sensitive Information into Log File"), A09,
  ]),
  "third-party-resources": entry("Third-party resource integrity", "Supply Chain", [
    cwe(353, "Missing Support for Integrity Check"), A03, A08,
  ]),
});

export function securityCheckDescriptors() {
  const excludedAliases = new Set(["dependency-advisory", "dependency-audit-unavailable"]);
  return Object.entries(SECURITY_RULE_CATALOG)
    .filter(([id]) => !excludedAliases.has(id))
    .map(([id, descriptor]) => ({ id, name: descriptor.name, category: descriptor.category }));
}

export function securityStandards(ruleId) {
  const descriptor = SECURITY_RULE_CATALOG[ruleId];
  if (!descriptor) return { standards: [], references: [] };
  return {
    standards: descriptor.standards.map((standard) => ({ ...standard })),
    references: [...descriptor.references],
  };
}
