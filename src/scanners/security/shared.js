import { lineOf } from "../../core/files.js";

export function normalizeName(file) {
  return String(file?.name ?? file?.relative?.split("/").at(-1) ?? "").toLowerCase();
}

export function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

export function truncate(value, maximum = 220) {
  const compact = String(value ?? "").replace(/\s+/g, " ").trim();
  return compact.length > maximum ? `${compact.slice(0, maximum - 1)}…` : compact;
}

export function packageLine(text, key) {
  const quoted = JSON.stringify(key);
  return lineOf(text, Math.max(0, text.indexOf(quoted)));
}
