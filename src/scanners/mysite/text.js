import { lineOf } from "../../core/files.js";

export function compact(value, max = 220) {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function blankComment(match) {
  return match.replace(/[^\r\n]/g, " ");
}

export function matchAt(text, pattern) {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const match = new RegExp(pattern.source, flags).exec(text);
  return match ? { index: match.index, match } : null;
}

export function lineAt(text, index) {
  return lineOf(text, Math.max(0, index));
}

export function isHtmlDocument(file) {
  return file.extension === ".html" || file.extension === ".htm";
}

export function isMarkdownDocument(file) {
  return file.extension === ".md" || file.extension === ".mdx";
}

export function regexEscape(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
