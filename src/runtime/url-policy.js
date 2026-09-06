import net from "node:net";

function stripIpv6Brackets(hostname) {
  return String(hostname).replace(/^\[|\]$/g, "");
}

export function isLoopbackHostname(hostname) {
  const normalized = stripIpv6Brackets(hostname).replace(/\.$/, "").toLowerCase();
  if (normalized === "localhost" || normalized.endsWith(".localhost")) return true;
  const ipVersion = net.isIP(normalized);
  if (ipVersion === 4) return normalized.split(".")[0] === "127";
  if (ipVersion === 6) {
    return normalized === "::1"
      || normalized === "0:0:0:0:0:0:0:1"
      || /^::ffff:127(?:\.\d{1,3}){3}$/i.test(normalized);
  }
  return false;
}

export function safeDisplayUrl(value) {
  try {
    const parsed = new URL(String(value));
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return "<invalid URL>";
  }
}

export function redactUrlQueries(value) {
  return String(value ?? "").replace(/\b(?:https?|wss?):\/\/[^\s<>"'`]+/gi, (candidate) => safeDisplayUrl(candidate));
}

export function isRuntimeNetworkUrlAllowed(value, { allowRemote = false } = {}) {
  let parsed;
  try {
    parsed = new URL(String(value));
  } catch {
    return false;
  }
  if (["data:", "about:"].includes(parsed.protocol)) return true;
  if (parsed.protocol === "blob:") {
    const embedded = parsed.pathname;
    return allowRemote || isRuntimeNetworkUrlAllowed(embedded, { allowRemote: false });
  }
  if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) return false;
  return allowRemote || isLoopbackHostname(parsed.hostname);
}
