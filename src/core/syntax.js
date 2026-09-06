// Bounded lexical helpers: never evaluate repository JavaScript. Unsupported
// expressions stay opaque rather than becoming evidence of a safe value.
export function javascriptTokens(source) {
  const tokens = [];
  let index = 0;
  while (index < source.length) {
    const start = index;
    const character = source[index];
    if (/\s/.test(character)) { index += 1; continue; }
    if (source.startsWith("//", index)) {
      while (index < source.length && !/[\r\n]/.test(source[index])) index += 1;
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      index = end < 0 ? source.length : end + 2;
      continue;
    }
    if (["'", '"', "`"].includes(character)) {
      index += 1;
      while (index < source.length) {
        if (source[index] === "\\") { index += 2; continue; }
        if (source[index++] === character) break;
      }
      const raw = source.slice(start, index);
      tokens.push({ kind: character === "`" ? "template" : "string", value: raw.slice(1, -1), raw, start, end: index });
      continue;
    }
    if (character === "/" && (!tokens.length || /^(?:[=(:,[!{;]|return|throw|=>)$/.test(tokens.at(-1).value))) {
      let cursor = index + 1;
      let inClass = false;
      for (; cursor < source.length && !/[\r\n]/.test(source[cursor]); cursor += 1) {
        if (source[cursor] === "\\") { cursor += 1; continue; }
        if (source[cursor] === "[") inClass = true;
        if (source[cursor] === "]") inClass = false;
        if (source[cursor] === "/" && !inClass) break;
      }
      if (source[cursor] === "/") {
        cursor += 1;
        while (/[a-z]/i.test(source[cursor] ?? "")) cursor += 1;
        index = cursor;
        tokens.push({ kind: "regex", value: source.slice(start, index), start, end: index });
        continue;
      }
    }
    const word = /^[A-Za-z_$][\w$]*|^\d+(?:\.\d+)?/.exec(source.slice(index));
    if (word) index += word[0].length;
    else index += /^(?:===|!==|=>|==|!=|\?\.|&&|\|\||\?\?|\+=|-=|\+\+|--|\.\.\.)/.exec(source.slice(index))?.[0].length ?? 1;
    tokens.push({ kind: word ? "word" : "punctuation", value: source.slice(start, index), start, end: index });
  }
  return tokens;
}

export function closingToken(tokens, opening) {
  const closing = { "(": ")", "[": "]", "{": "}" };
  const stack = [];
  for (let index = opening; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.kind !== "punctuation") continue;
    if (closing[token.value]) stack.push(closing[token.value]);
    else if ([")", "]", "}"].includes(token.value)) {
      if (stack.pop() !== token.value) return -1;
      if (!stack.length) return index;
    }
  }
  return -1;
}

export function tokenArguments(tokens, opening, end = closingToken(tokens, opening)) {
  if (end < 0) return [];
  const arguments_ = [];
  let start = opening + 1;
  for (let index = start; index < end; index += 1) {
    if (tokens[index].kind !== "punctuation") continue;
    if (["(", "[", "{"].includes(tokens[index].value)) {
      const close = closingToken(tokens, index);
      if (close < 0 || close > end) return [];
      index = close;
    } else if (tokens[index].value === ",") {
      arguments_.push(tokens.slice(start, index));
      start = index + 1;
    }
  }
  arguments_.push(tokens.slice(start, end));
  return arguments_;
}

/** Mask foreign/inert HTML and raw-text contents without moving source offsets. */
export function htmlDocumentSurface(source) {
  const output = source.split("");
  const stack = [];
  const hidden = new Set(["svg", "math", "template", "script", "style", "textarea"]);
  const token = /<!--[\s\S]*?-->|<\/?([A-Za-z][\w:-]*)\b(?:"[^"]*"|'[^']*'|[^'">])*>/g;
  const blank = (start, end) => {
    for (let index = start; index < end; index += 1) if (!/[\r\n]/.test(source[index])) output[index] = " ";
  };
  let previous = 0;
  for (const match of source.matchAll(token)) {
    if (stack.length) blank(previous, match.index);
    const name = match[1]?.toLowerCase();
    const closing = match[0].startsWith("</");
    if (!name) blank(match.index, match.index + match[0].length);
    else if (stack.length || hidden.has(name)) {
      blank(match.index, match.index + match[0].length);
      if (closing && stack.at(-1) === name) stack.pop();
      else if (!closing && hidden.has(name) && !/\/\s*>$/.test(match[0])
        && !["script", "style", "textarea"].includes(stack.at(-1))) stack.push(name);
    }
    previous = match.index + match[0].length;
  }
  if (stack.length) blank(previous, source.length);
  return output.join("");
}
