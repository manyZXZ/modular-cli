import { javascriptTokens, closingToken, tokenArguments } from "../core/syntax.js";

const IDENTIFIER = String.raw`[A-Za-z_$][\w$]*`;
const SERVER_PATH = /(?:^|\/)(?:api|backend|controllers?|handlers?|middleware|server)(?:\/|$)|(?:^|\/)(?:route|server|middleware)\.[cm]?[jt]sx?$/i;
const SERVER_RUNTIME = /(?:from\s*["'](?:node:)?(?:child_process|fs(?:\/promises)?|http|https|net|tls)["']|require\s*\(\s*["'](?:node:)?(?:child_process|fs(?:\/promises)?|http|https|net|tls)["']\s*\)|from\s*["'](?:express|fastify|hapi|koa|next\/server|pg|mysql2?|sequelize|knex)["']|\b(?:NextRequest|NextResponse|FastifyRequest|RequestHandler)\b)/i;
const REQUEST_SOURCE = /\b(?:req(?:uest)?|ctx|context|event)\s*(?:\.\s*(?:query|body|params|headers|url|originalUrl)|\[\s*["'](?:query|body|params|headers|url|originalUrl)["']\s*\]|\.\s*(?:json|formData)\s*\()|\b(?:searchParams|formData)\s*\.\s*get\s*\(|\b(?:getQuery|readBody|getRouterParam)\s*\(\s*(?:event|req(?:uest)?|ctx|context)\b/i;
const DIRECT_REQUEST_SOURCE = new RegExp(REQUEST_SOURCE.source, "i");

function maskJavaScriptNonCode(text) {
  const source = String(text);
  const output = source.split("");
  const templateExpressions = [];
  let mode = "code";
  let escaped = false;
  const mask = (index) => {
    if (source[index] !== "\r" && source[index] !== "\n") output[index] = " ";
  };

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (mode === "line-comment") {
      if (character === "\r" || character === "\n") mode = "code";
      else mask(index);
      continue;
    }
    if (mode === "block-comment") {
      mask(index);
      if (character === "*" && next === "/") {
        mask(index + 1);
        index += 1;
        mode = "code";
      }
      continue;
    }
    if (mode === "single" || mode === "double") {
      mask(index);
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if ((mode === "single" && character === "'") || (mode === "double" && character === "\"")) mode = "code";
      continue;
    }
    if (mode === "template") {
      if (escaped) {
        mask(index);
        escaped = false;
      } else if (character === "\\") {
        mask(index);
        escaped = true;
      } else if (character === "`") {
        mask(index);
        mode = "code";
      } else if (character === "$" && next === "{") {
        templateExpressions.push(1);
        index += 1;
        mode = "code";
      } else {
        mask(index);
      }
      continue;
    }

    if (character === "/" && next === "/") {
      mask(index);
      mask(index + 1);
      index += 1;
      mode = "line-comment";
    } else if (character === "/" && next === "*") {
      mask(index);
      mask(index + 1);
      index += 1;
      mode = "block-comment";
    } else if (character === "'") {
      mask(index);
      mode = "single";
    } else if (character === "\"") {
      mask(index);
      mode = "double";
    } else if (character === "`") {
      mask(index);
      mode = "template";
    } else if (templateExpressions.length > 0 && character === "{") {
      templateExpressions[templateExpressions.length - 1] += 1;
    } else if (templateExpressions.length > 0 && character === "}") {
      templateExpressions[templateExpressions.length - 1] -= 1;
      if (templateExpressions[templateExpressions.length - 1] === 0) {
        templateExpressions.pop();
        mode = "template";
      }
    }
  }
  return output.join("");
}

function maskJavaScriptComments(text) {
  const source = String(text);
  const output = source.split("");
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  const mask = (index) => {
    if (source[index] !== "\r" && source[index] !== "\n") output[index] = " ";
  };
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === "\r" || character === "\n") lineComment = false;
      else mask(index);
      continue;
    }
    if (blockComment) {
      mask(index);
      if (character === "*" && next === "/") {
        mask(index + 1);
        index += 1;
        blockComment = false;
      }
      continue;
    }
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === "\"" || character === "`") quote = character;
    else if (character === "/" && next === "/") {
      mask(index);
      mask(index + 1);
      index += 1;
      lineComment = true;
    } else if (character === "/" && next === "*") {
      mask(index);
      mask(index + 1);
      index += 1;
      blockComment = true;
    }
  }
  return output.join("");
}

function balancedCallContent(text, openingParenthesis, stopAtComma) {
  let quote = null;
  let escaped = false;
  const stack = ["("];
  for (let index = openingParenthesis + 1; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "(" || character === "[" || character === "{") stack.push(character);
    else if (character === ")" || character === "]" || character === "}") {
      stack.pop();
      if (stack.length === 0) return text.slice(openingParenthesis + 1, index).trim();
    } else if (stopAtComma && character === "," && stack.length === 1) {
      return text.slice(openingParenthesis + 1, index).trim();
    }
  }
  return text.slice(openingParenthesis + 1, Math.min(text.length, openingParenthesis + 500)).trim();
}

function identifierPresent(expression, identifier) {
  return new RegExp(`(^|[^\\w$])${identifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^\\w$]|$)`).test(expression);
}

function requestSourceLabel(expression) {
  if (/\.(?:query|body|params)\b|\[["'](?:query|body|params)["']\]/i.test(expression)) return "request query/body/route data";
  if (/\.headers\b|\[["']headers["']\]/i.test(expression)) return "request header data";
  if (/\.(?:url|originalUrl)\b/i.test(expression)) return "request URL data";
  if (/searchParams/i.test(expression)) return "URL search-parameter data";
  if (/formData/i.test(expression)) return "submitted form data";
  if (/\b(?:getQuery|readBody|getRouterParam)\b/.test(expression)) return "server request data";
  return "request-controlled data";
}

function transparentlyPropagates(expression) {
  const calls = [...String(expression).matchAll(/\b(?:new\s+)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g)]
    .map((match) => match[1].replace(/\s+/g, ""));
  if (calls.length === 0) return true;
  const transparent = /^(?:URL|String|decodeURI|decodeURIComponent|path\.(?:join|resolve|normalize)|[A-Za-z_$][\w$]*\.(?:trim|replace|toString))$/;
  return calls.every((callee) => transparent.test(callee));
}

function lexicalScopes(text) {
  const scopes = [{ start: -1, end: text.length + 1 }];
  const stack = [];
  let quote = null;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "{") stack.push(index);
    else if (character === "}" && stack.length > 0) {
      const start = stack.pop();
      scopes.push({ start, end: index });
    }
  }
  return scopes;
}

function scopeAt(scopes, index) {
  return scopes
    .filter((scope) => scope.start < index && index < scope.end)
    .sort((left, right) => right.start - left.start || left.end - right.end)[0];
}

function visibleTaint(bindings, name, index) {
  const binding = bindings
    .filter((entry) => entry.name === name
      && entry.index < index
      && entry.scope.start < index
      && index < entry.scope.end)
    .sort((left, right) => right.scope.start - left.scope.start || right.index - left.index)[0] ?? null;
  return binding?.tainted === true ? binding : null;
}

function collectTaint(text) {
  const bindings = [];
  const analysisText = maskJavaScriptNonCode(text);
  const scopes = lexicalScopes(analysisText);
  const assignments = [];
  const assignmentPattern = new RegExp(String.raw`\b(?:const|let|var)\s+(${IDENTIFIER})\s*=\s*([^;\r\n]+)`, "g");
  for (const match of analysisText.matchAll(assignmentPattern)) {
    const binding = {
      name: match[1],
      expression: match[2],
      index: match.index ?? 0,
      nameIndex: match.index + match[0].indexOf(match[1]),
      scope: scopeAt(scopes, match.index ?? 0),
      tainted: false,
    };
    assignments.push(binding);
    bindings.push(binding);
  }
  // Reassignments are evaluated in order. A conditional write can introduce
  // taint but cannot prove that a previously tainted binding became safe.
  const reassignmentPattern = new RegExp(String.raw`(?<![\w$.])(${IDENTIFIER})\s*=(?!=|>)\s*([^;\r\n]+)`, "g");
  for (const match of analysisText.matchAll(reassignmentPattern)) {
    const index = match.index;
    if (assignments.some((entry) => entry.nameIndex === index)) continue;
    const declaration = bindings.filter((entry) => entry.name === match[1] && entry.index < index
      && entry.scope.start < index && index < entry.scope.end)
      .sort((a, b) => b.scope.start - a.scope.start || b.index - a.index)[0];
    if (!declaration) continue;
    const scope = scopeAt(scopes, index);
    const assignment = { name: match[1], expression: match[2], index,
      scope: declaration.scope, conditional: scope !== declaration.scope
        || /\b(?:if|while|for)\s*\([^;{}]*\)\s*$/.test(analysisText.slice(declaration.index, index)),
      tainted: false };
    assignments.push(assignment);
    bindings.push(assignment);
  }
  const destructuringPattern = new RegExp(String.raw`\b(?:const|let|var)\s*\{([^}\r\n]+)\}\s*=\s*([^;\r\n]+)`, "g");
  for (const match of analysisText.matchAll(destructuringPattern)) {
    const direct = DIRECT_REQUEST_SOURCE.test(match[2]);
    for (const property of match[1].split(",")) {
      const pieces = property.trim().split(/\s*:\s*/);
      const name = (pieces[1] ?? pieces[0] ?? "").replace(/\s*=.*$/, "").trim();
      if (!new RegExp(`^${IDENTIFIER}$`).test(name)) continue;
      bindings.push({
        name,
        index: match.index ?? 0,
        scope: scopeAt(scopes, match.index ?? 0),
        tainted: direct,
        source: direct ? requestSourceLabel(match[2]) : null,
        sourceName: direct ? name : null,
        sanitizedPath: false,
      });
    }
  }

  assignments.sort((left, right) => left.index - right.index);
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const assignment of assignments) {
      if (assignment.tainted) continue;
      const direct = DIRECT_REQUEST_SOURCE.test(assignment.expression);
      const upstream = bindings.find((entry) => entry.tainted
        && identifierPresent(assignment.expression, entry.name)
        && visibleTaint(bindings, entry.name, assignment.index) === entry);
      const previous = assignment.conditional ? visibleTaint(bindings, assignment.name, assignment.index) : null;
      if (!direct && !upstream && !previous) continue;
      // An arbitrary helper can be a validator or an allowlist mapper. Carrying
      // taint through it without interprocedural analysis creates noisy claims;
      // only transparent language/path/URL transforms are followed here.
      if (!direct && !previous && !transparentlyPropagates(assignment.expression)) continue;
      const source = direct ? requestSourceLabel(assignment.expression) : (upstream ?? previous).source;
      Object.assign(assignment, {
        tainted: true,
        source,
        sourceName: direct ? assignment.name : (upstream ?? previous).sourceName,
        sanitizedPath: /\bpath\s*\.\s*basename\s*\(/.test(assignment.expression)
          || /\b(?:sanitize|safe)(?:File|Path|Name)\s*\(/i.test(assignment.expression)
          || upstream?.sanitizedPath === true,
      });
      changed = true;
    }
    if (!changed) break;
  }
  return bindings;
}

function taintIn(expression, bindings, index) {
  const analysisExpression = maskJavaScriptNonCode(expression);
  if (DIRECT_REQUEST_SOURCE.test(analysisExpression)) {
    return { source: requestSourceLabel(analysisExpression), sourceName: null, variable: null, direct: true, sanitizedPath: false };
  }
  for (const name of [...new Set(bindings.map((entry) => entry.name))]) {
    if (!identifierPresent(analysisExpression, name)) continue;
    const detail = visibleTaint(bindings, name, index);
    if (detail) return { ...detail, variable: name, direct: false };
  }
  return null;
}

function hasFixedRemoteOrigin(expression) {
  // Only a literal prefix of the actual destination fixes its authority.
  // A second URL argument is merely a base; absolute input overrides it.
  const value = expression.trim().replace(/^new\s+URL\s*\(\s*/, "");
  return /^["'`]https?:\/\/[A-Za-z0-9.-]+(?::\d+)?\//.test(value);
}

function terminatingGuard(pattern, text) {
  const condition = new RegExp(String.raw`\bif\s*\(\s*${pattern}\s*\)`, "gi");
  const code = maskJavaScriptNonCode(text);
  return [...text.matchAll(condition)].some((match) => {
    if (!/\bif\b/.test(code.slice(match.index, match.index + 2))) return false;
    return terminatingBody(text.slice(match.index + match[0].length));
  });
}

function terminatingBody(text) {
  const tokens = javascriptTokens(text.slice(0, 1000));
  const first = tokens[0]?.value === "{" ? tokens[1] : tokens[0];
  // Only direct exits are established. Nested conditional exits, helper calls,
  // comments, and string literals cannot establish a control-flow guard.
  return first?.kind === "word" && ["return", "throw"].includes(first.value);
}

function hasPathContainment(text, variable, sinkIndex, scopeStart = 0) {
  if (!variable) return false;
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const before = maskJavaScriptComments(text.slice(Math.max(scopeStart + 1, sinkIndex - 1_500), sinkIndex));
  const unsafePrefix = String.raw`!\s*${escaped}\s*\.\s*startsWith\s*\([^\r\n)]{0,180}(?:(?:path\s*\.)?sep|["'](?:\\\\|\/)["'])[^\r\n)]*\)`;
  if (terminatingGuard(unsafePrefix, before)) return true;

  const relative = new RegExp(
    String.raw`\b(?:const|let)\s+(${IDENTIFIER})\s*=\s*(?:path\s*\.)?relative\s*\([^\r\n]{0,180}${escaped}\b`,
    "i",
  ).exec(before);
  if (!relative) return false;
  const relativeName = relative[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return terminatingGuard(
    String.raw`${relativeName}\s*\.\s*startsWith\s*\(\s*["']\.\.["']\s*\)(?:\s*\|\|\s*(?:path\s*\.)?isAbsolute\s*\(\s*${relativeName}\s*\))?`,
    before.slice(relative.index + relative[0].length),
  );
}

function strictFilenameRegexBody(body) {
  // An anchored allowlist may contain escaped literal dots and bounded groups,
  // but wildcard/directory-separator classes are not filename containment.
  let atomsSafe = true;
  const outsideClasses = body.replace(/\[(?:\\.|[^\]\\])*\]/g, (atom) => {
    try {
      const matcher = new RegExp(`^(?:${atom})$`, "u");
      if (atom.startsWith("[^") || matcher.test("/") || matcher.test("\\")) atomsSafe = false;
    } catch { atomsSafe = false; }
    return "x";
  });
  if (!atomsSafe || /\[|\]/.test(outsideClasses)) return false;
  const outsideEscapes = outsideClasses.replace(/\\(?:u[0-9a-f]{4}|x[0-9a-f]{2}|.)/gi, (atom) => {
    try {
      const matcher = new RegExp(`^(?:${atom})$`, "u");
      if (!/^\\(?:[dw.()_-]|u[0-9a-f]{4}|x[0-9a-f]{2})$/i.test(atom)
        || matcher.test("/") || matcher.test("\\")) atomsSafe = false;
    } catch { atomsSafe = false; }
    return "x";
  });
  if (!atomsSafe || /[^A-Za-z0-9_(),{}?:|+*\-]/.test(outsideEscapes)
    || /\(\?(?!:)/.test(outsideEscapes)) return false;
  // A top-level alternation weakens one or both anchors (`^foo|bar$`). Only
  // alternation nested inside an explicit group is accepted.
  let depth = 0;
  let escaped = false;
  let inClass = false;
  for (const character of body) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === "[") inClass = true;
    else if (character === "]") inClass = false;
    else if (!inClass && character === "(") depth += 1;
    else if (!inClass && character === ")") depth = Math.max(0, depth - 1);
    else if (!inClass && character === "|" && depth === 0) return false;
  }
  try {
    const validator = new RegExp(`^(?:${body})$`, "u");
    if ([".", "..", "/", "\\"].some((value) => validator.test(value))) return false;
  } catch { return false; }
  return true;
}

function hasStrictFilenameValidation(text, variable, sinkIndex, scopeStart = 0) {
  if (!variable) return false;
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const before = maskJavaScriptComments(text.slice(Math.max(scopeStart + 1, sinkIndex - 2_000), sinkIndex));
  if (hasFilenamePartRejection(before, variable)) return true;
  const code = maskJavaScriptNonCode(before);
  const direct = new RegExp(
    String.raw`\bif\s*\(\s*!\s*\/\^((?:\\.|[^\/\r\n]){1,240})\$\/[diuv]*\s*\.\s*test\s*\(\s*${escaped}\s*\)\s*\)`,
    "i",
  ).exec(before);
  if (direct && code.slice(direct.index, direct.index + 2) === "if" && strictFilenameRegexBody(direct[1])
    && terminatingBody(before.slice(direct.index + direct[0].length))) return true;

  const namedUse = new RegExp(
    String.raw`\b(${IDENTIFIER})\s*=\s*${escaped}\s*\.\s*match\s*\(\s*(${IDENTIFIER})\s*\)[\s\S]{0,300}?if\s*\(\s*!\s*\1\s*\)[\s\S]{0,300}?\b(?:return|throw)\b`,
    "i",
  ).exec(before);
  if (!namedUse || code.slice(namedUse.index, namedUse.index + namedUse[1].length) !== namedUse[1]) return false;
  const declaration = new RegExp(
    String.raw`\b(?:const|let|var)\s+${namedUse[2]}\s*=\s*\/\^((?:\\.|[^\/\r\n]){1,240})\$\/[diuv]*(?![a-z])`,
    "i",
  ).exec(before);
  return Boolean(declaration && /^(?:const|let|var)\b/.test(code.slice(declaration.index)) && strictFilenameRegexBody(declaration[1])
    && terminatingGuard(String.raw`!\s*${namedUse[1]}`, before));
}

function hasFilenamePartRejection(before, variable) {
  const tokens = javascriptTokens(before);
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].kind !== "word" || tokens[index].value !== "if" || tokens[index + 1]?.value !== "(") continue;
    const close = closingToken(tokens, index + 1);
    if (close < 0 || !terminatingBody(before.slice(tokens[close].end))) continue;
    const rejected = new Set();
    let cursor = index + 2;
    for (; cursor < close;) {
      const part = tokens.slice(cursor, cursor + 6);
      if (part[0]?.value !== variable || part[1]?.value !== "." || part[2]?.value !== "includes"
        || part[3]?.value !== "(" || part[4]?.kind !== "string" || part[5]?.value !== ")") break;
      // Decode only the short literals used for path separators, never code.
      rejected.add(part[4].value.replace(/\\\\/g, "\\"));
      cursor += 6;
      if (cursor < close && tokens[cursor]?.value === "||") cursor += 1;
      else break;
    }
    if (cursor !== close || !["/", "\\", ".."].every((part) => rejected.has(part))) continue;
    const after = before.slice(tokens[close].end);
    const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(String.raw`\b${escaped}\s*(?:=(?!=)|\+=)|\bdecodeURI(?:Component)?\s*\(`).test(after)) continue;
    if (rejected.has(":")) return true;
    // A required literal prefix also excludes Windows drive-relative paths.
    // Without either it or a colon rejection, C:foo could escape a base path.
    const validation = new RegExp(String.raw`\b(?:const|let)\s+(${IDENTIFIER})\s*=\s*\/\^([A-Za-z0-9_-]+[^|\r\n]{0,220})\$\/[diu]*(?![a-z])`).exec(after);
    if (!validation) continue;
    const prefix = /^[A-Za-z0-9_-]+/.exec(validation[2])?.[0] ?? "";
    if (prefix.length < 2 || /[?*{]/.test(validation[2][prefix.length] ?? "")) continue;
    const code = maskJavaScriptNonCode(after);
    if (!/^(?:const|let)\b/.test(code.slice(validation.index))) continue;
    const match = new RegExp(String.raw`\b(?:const|let)\s+(${IDENTIFIER})\s*=\s*${escaped}\.match\(\s*${validation[1]}\s*\)`).exec(after);
    if (match && /^(?:const|let)\b/.test(code.slice(match.index))
      && terminatingGuard(String.raw`!\s*${match[1]}`, after.slice(match.index + match[0].length))) return true;
  }
  return false;
}

function hasUrlAllowlist(text, variable, sinkIndex, scopeStart = 0) {
  if (!variable) return false;
  const escaped = variable.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const start = Math.max(scopeStart + 1, sinkIndex - 1_500);
  const before = maskJavaScriptComments(text.slice(start, sinkIndex));
  const membership = String.raw`!\s*(?:allowed(?:Origins?|Hosts?|Urls?)?|[A-Z_$][A-Z0-9_$]*)\s*\.\s*(?:has|includes)\s*\(\s*${escaped}\s*\.\s*(?:origin|hostname)\s*\)`;
  const exactHost = String.raw`${escaped}\s*\.\s*(?:origin|hostname)\s*!==?\s*["'](?:https?:\/\/)?[A-Za-z0-9.-]+(?::\d+)?["']`;
  const condition = new RegExp(String.raw`\bif\s*\(\s*(?:${membership}|${exactHost})\s*\)`, "g");
  const guards = [...before.matchAll(condition)];
  if (guards.length === 0) return false;
  const code = maskJavaScriptNonCode(text);
  const scopes = lexicalScopes(code);
  const tokens = javascriptTokens(text.slice(0, sinkIndex));
  return guards.some((match) => {
    const guardIndex = start + match.index;
    const guardEnd = guardIndex + match[0].length;
    if (code.slice(guardIndex, guardIndex + 2) !== "if"
      || !terminatingBody(text.slice(guardEnd))) return false;

    // A guard in a different branch/function cannot establish a condition at
    // this sink. Use the full source so the look-back limit cannot hide a block.
    const scope = scopeAt(scopes, guardIndex);
    if (!(scope.start < sinkIndex && sinkIndex < scope.end)) return false;
    const tokenIndex = tokens.findIndex((token) => token.start === guardIndex);
    if (tokenIndex < 0 || isControlledStatement(tokens, tokenIndex)) return false;
    const bodyEnd = terminatingGuardBodyEnd(text, guardEnd);
    if (bodyEnd === null || sinkIndex < bodyEnd) return false;

    const after = code.slice(bodyEnd, sinkIndex);
    // Any intervening write invalidates this value's guard, including URL
    // property writes and destructuring. Comparison operators are not writes.
    const write = new RegExp(String.raw`(?<![\w$.])${escaped}\s*(?:(?:\??\.\s*[A-Za-z_$][\w$]*|\[[^\]\r\n]*\])\s*)*(?:=(?!=|>)|(?:\+|-|\*\*?|/|%|&&?|\|\|?|\^|\?\?)=|\+\+|--)`);
    if (write.test(after)
      || new RegExp(String.raw`(?:\+\+|--)\s*${escaped}\b`).test(after)
      || new RegExp(String.raw`[\[{][^;\r\n]*\b${escaped}\b[^;\r\n]*[\]}]\s*=(?!=)`).test(after)) return false;
    // A later case label permits entry after the guard even in the same block.
    return !tokens.some((token) => token.start > guardEnd && ["case", "default"].includes(token.value)
      && scopeAt(scopes, token.start) === scope);
  });
}

function isControlledStatement(tokens, index) {
  const previous = tokens[index - 1];
  if (!previous || ["{", "}", ";"].includes(previous.value)) return false;
  if (["else", "do", ":", "=>"].includes(previous.value)) return true;
  // Unbraced if/loop bodies can start with a guard at the same brace depth.
  if (previous.value === ")") {
    let depth = 1;
    for (let cursor = index - 2; cursor >= 0; cursor -= 1) {
      if (tokens[cursor].kind !== "punctuation") continue;
      if (tokens[cursor].value === ")") depth += 1;
      if (tokens[cursor].value !== "(" || --depth !== 0) continue;
      const owner = tokens[cursor - 1]?.value === "await" ? tokens[cursor - 2]?.value : tokens[cursor - 1]?.value;
      return ["if", "while", "for", "with", "catch", "switch"].includes(owner);
    }
  }
  return false;
}

function terminatingGuardBodyEnd(text, offset) {
  const source = text.slice(offset, offset + 1_000);
  const tokens = javascriptTokens(source);
  if (tokens[0]?.value === "{") {
    const end = closingToken(tokens, 0);
    return end < 0 ? null : offset + tokens[end].end;
  }
  if (!["return", "throw"].includes(tokens[0]?.value)) return null;
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    const newline = /[\r\n]/.test(source.slice(tokens[index - 1].end, token.start));
    if (newline && (index === 1 && tokens[0].value === "return"
      || ["return", "throw", "if", "const", "let", "var"].includes(token.value))) {
      return offset + token.start;
    }
    if (token.kind !== "punctuation") continue;
    if (token.value === ";") return offset + token.end;
    if (token.value === "}") return offset + token.start;
    if (["(", "[", "{"].includes(token.value)) {
      const end = closingToken(tokens, index);
      if (end < 0) return null;
      index = end;
    }
  }
  return null;
}

function isParameterizedSqlConfig(argument) {
  const expression = String(argument).trim();
  if (!expression.startsWith("{")) return false;
  const staticText = /\btext\s*:\s*(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\[\s\S]|\$(?!\{)|[^\\`$])*`)\s*(?=[,}])/.test(expression);
  return staticText && /\bvalues\s*:/.test(expression);
}

function callSignals(text, regex, callback, analysisText = text) {
  regex.lastIndex = 0;
  let match;
  while ((match = regex.exec(analysisText)) !== null) {
    const opening = analysisText.indexOf("(", match.index);
    if (opening === -1) continue;
    callback({
      match,
      index: match.index,
      argument: balancedCallContent(text, opening, true),
      call: balancedCallContent(text, opening, false),
      analysisArgument: balancedCallContent(analysisText, opening, true),
      analysisCall: balancedCallContent(analysisText, opening, false),
    });
    if (match[0].length === 0) regex.lastIndex += 1;
  }
}

export function isLikelyServerSource(file, text) {
  const relative = String(file?.relative ?? "").replace(/\\/g, "/");
  const runtime = SERVER_RUNTIME.test(maskJavaScriptComments(text));
  if (runtime) return true;
  if (!SERVER_PATH.test(relative)) return false;
  if (/(?:^|\/)pages\/api(?:\/|$)|(?:^|\/)app\/api\/.+\/route\.[cm]?[jt]sx?$/i.test(relative)) return true;
  // `api` is also a common browser-client directory. Ambiguous API wrappers
  // need a real server runtime/import signal; route/handler/server paths retain
  // their stronger framework convention.
  return !/(?:^|\/)api(?:\/|$)/i.test(relative)
    || /(?:^|\/)(?:routes?|controllers?|handlers?|middleware|server)(?:\/|\.)/i.test(relative);
}

/** Returns narrowly scoped, one-file source-to-sink signals. */
export function serverDataFlowSignals(file, text) {
  if (!isLikelyServerSource(file, text)) return [];
  const tainted = collectTaint(text);
  const analysisText = maskJavaScriptNonCode(text);
  const signals = [];
  const seen = new Set();

  function add(ruleId, index, detail) {
    const key = `${ruleId}:${index}`;
    if (seen.has(key)) return;
    seen.add(key);
    signals.push({ ruleId, index, ...detail });
  }

  callSignals(text, /(?<![\w$.])(?:globalThis\s*\.\s*)?(?:fetch|got|request)\s*\(|\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(|\b(?:http|https)\s*\.\s*(?:get|request)\s*\(/g, ({ match, index, argument }) => {
    const taint = taintIn(argument, tainted, index);
    const sink = match[0].replace(/\s*\($/, "").trim();
    if (/^(?:got|request)$/.test(sink)
      && !new RegExp(String.raw`(?:from\s*["'](?:got|request)["']|require\s*\(\s*["'](?:got|request)["']\s*\))`).test(text)) return;
    if (!taint || hasFixedRemoteOrigin(argument) || hasUrlAllowlist(text, taint.variable, index, taint.scope?.start)) return;
    add("server-ssrf", index, {
      title: "Request-controlled URL reaches a server-side network client",
      category: "Application Security",
      severity: "high",
      confidence: "medium",
      manual: true,
      description: `${taint.source} flows into ${sink}, which may let an attacker make the server contact internal or attacker-controlled services.`,
      recommendation: "Resolve the URL, require https:, compare the normalized hostname and port against a strict allowlist, block private/link-local address ranges after DNS resolution, and apply redirect and response-size limits.",
      evidence: `Data flow: ${taint.source}${taint.variable ? ` -> ${taint.variable}` : ""} -> server network request`,
      tags: ["ssrf", "data-flow", "server", "manual-review"],
    });
  }, analysisText);

  const pathSink = /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|download|unlink|unlinkSync|rm|rmSync|rename)\s*\(/g;
  callSignals(text, pathSink, ({ match, index, argument, call }) => {
    const taint = taintIn(argument, tainted, index);
    const frameworkFileResponse = /\b(?:sendFile|download)\s*\(/.test(match[0]);
    const importsFilesystem = /(?:from\s*["'](?:node:)?fs(?:\/promises)?["']|require\s*\(\s*["'](?:node:)?fs(?:\/promises)?["']\s*\)|\bfs\s*\.\s*(?:read|write|create|unlink|rm|rename))/i.test(text);
    if (!frameworkFileResponse && !importsFilesystem) return;
    if (!taint || taint.sanitizedPath || /\bpath\s*\.\s*basename\s*\(/.test(argument)) return;
    if (hasStrictFilenameValidation(text, taint.sourceName, index, taint.scope?.start)) return;
    if (frameworkFileResponse && /\broot\s*:/.test(call)) return;
    if (hasPathContainment(text, taint.variable, index, taint.scope?.start)) return;
    add("server-path-traversal", index, {
      title: "Request-controlled path reaches a filesystem operation",
      category: "Application Security",
      severity: "high",
      confidence: "medium",
      manual: true,
      description: `${taint.source} flows into ${match[0].replace(/\s*\($/, "").trim()} without a visible basename or containment check. Attackers may be able to read, overwrite, move, or delete files outside the intended directory.`,
      recommendation: "Map an opaque identifier to a server-owned filename, or resolve against a fixed base directory and reject absolute paths and any normalized result outside that base. Do not rely on removing '../' substrings.",
      evidence: `Data flow: ${taint.source}${taint.variable ? ` -> ${taint.variable}` : ""} -> filesystem path`,
      tags: ["path-traversal", "data-flow", "server", "manual-review"],
    });
  }, analysisText);

  if (/(?:from\s*["'](?:node:)?child_process["']|require\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process\s*\.\s*exec)/.test(text)) {
    callSignals(text, /(^|[^\w$.])(?:child_process\s*\.\s*)?exec(?:Sync)?\s*\(/gm, ({ match, index, argument }) => {
      const taint = taintIn(argument, tainted, index);
      if (!taint) return;
      add("server-command-injection", index + (match[1]?.length ?? 0), {
        title: "Request-controlled data reaches a shell command",
        category: "Application Security",
        severity: "critical",
        confidence: "high",
        manual: true,
        description: `${taint.source} flows into a shell-executing child-process API. Shell metacharacters may allow arbitrary command execution under the application account.`,
        recommendation: "Replace exec/execSync with execFile or spawn using a fixed executable and an argument array, validate each argument against an allowlist, and run the process with least privilege.",
        evidence: `Data flow: ${taint.source}${taint.variable ? ` -> ${taint.variable}` : ""} -> shell command`,
        tags: ["command-injection", "data-flow", "server", "manual-review"],
      });
    }, analysisText);
    callSignals(text, /(^|[^\w$.])(?:child_process\s*\.\s*)?spawn(?:Sync)?\s*\(/gm, ({ match, index, call }) => {
      if (!/\bshell\s*:\s*(?:true|["'][^"'\r\n]+["'])\s*(?=[,}])/i.test(call)) return;
      const taint = taintIn(call, tainted, index);
      if (!taint) return;
      add("server-command-injection", index + (match[1]?.length ?? 0), {
        title: "Request-controlled executable reaches a shell-enabled process",
        category: "Application Security",
        severity: "critical",
        confidence: "high",
        manual: true,
        description: `${taint.source} flows into a spawn API whose shell option is enabled. The shell reparses the command and may interpret attacker-controlled metacharacters.`,
        recommendation: "Keep shell:false, use a fixed executable, pass each validated argument in the argument array, and run the child process with least privilege.",
        evidence: `Data flow: ${taint.source}${taint.variable ? ` -> ${taint.variable}` : ""} -> shell-enabled child process`,
        tags: ["command-injection", "data-flow", "server", "manual-review"],
      });
    }, analysisText);
  }

  callSignals(text, /\b(?:[A-Za-z_$][\w$]*\s*\.\s*(?:query|execute|raw)|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/g, ({ match, index, argument }) => {
    const taint = taintIn(argument, tainted, index);
    const likelySql = /\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|DROP|ALTER|CREATE|CALL)\b/i.test(argument)
      || /\b(?:db|database|pool|sql|client|connection|sequelize|prisma|knex)\s*\./i.test(match[0])
      || /from\s*["'](?:pg|mysql2?|sequelize|knex|@prisma\/client)["']/i.test(text);
    if (!taint || !likelySql || isParameterizedSqlConfig(argument)) return;
    add("server-sql-injection", index, {
      title: "Request-controlled data reaches a SQL statement",
      category: "Application Security",
      severity: "critical",
      confidence: "high",
      manual: true,
      description: `${taint.source} flows into the SQL text argument of ${match[0].replace(/\s*\($/, "").trim()}. Concatenated or interpolated values can change query structure.`,
      recommendation: "Use the database driver's parameter placeholders or a non-raw typed query builder. Keep identifiers on a strict allowlist because table and column names usually cannot be parameterized.",
      evidence: `Data flow: ${taint.source}${taint.variable ? ` -> ${taint.variable}` : ""} -> SQL text`,
      tags: ["sql-injection", "data-flow", "server", "manual-review"],
    });
  }, analysisText);

  return signals.sort((left, right) => left.index - right.index || left.ruleId.localeCompare(right.ruleId));
}

function workflowRunRanges(text) {
  // Keep a possible trailing CR in each line so offsets remain exact for both
  // LF and CRLF input. The YAML regexes below intentionally accept whitespace.
  const lines = text.split("\n");
  const offsets = [];
  let offset = 0;
  for (const line of lines) {
    offsets.push(offset);
    offset += line.length + 1;
  }
  const ranges = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^(\s*)(?:-\s*)?run\s*:\s*(.*)$/.exec(lines[index].replace(/\r$/, ""));
    if (!match) continue;
    const indentation = match[1].length;
    let endLine = index;
    if (/^[>|][+-]?\s*$/.test(match[2].trim())) {
      while (endLine + 1 < lines.length) {
        const next = lines[endLine + 1];
        if (next.trim() && (next.match(/^\s*/)?.[0].length ?? 0) <= indentation) break;
        endLine += 1;
      }
    }
    ranges.push({
      start: offsets[index],
      end: offsets[endLine] + lines[endLine].length,
      text: lines.slice(index, endLine + 1).join("\n"),
    });
    index = endLine;
  }
  return ranges;
}

function maskYamlComments(text) {
  return String(text).split("\n").map((line) => {
    let quote = null;
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index];
      if (quote) {
        if (escaped) escaped = false;
        else if (character === "\\" && quote === "\"") escaped = true;
        else if (character === quote) quote = null;
      } else if (character === "'" || character === "\"") quote = character;
      else if (character === "#") return `${line.slice(0, index)}${" ".repeat(line.length - index)}`;
    }
    return line;
  }).join("\n");
}

function workflowJobRanges(text) {
  const source = maskYamlComments(text);
  const lines = source.split("\n");
  const offsets = [];
  let offset = 0;
  for (const line of lines) {
    offsets.push(offset);
    offset += line.length + 1;
  }
  const jobsLine = lines.findIndex((line) => /^\s*jobs\s*:\s*$/.test(line.replace(/\r$/, "")));
  if (jobsLine < 0) return [];
  const jobsIndent = lines[jobsLine].match(/^\s*/)?.[0].length ?? 0;
  let jobsEndLine = lines.length;
  let jobIndent = null;
  const starts = [];
  for (let index = jobsLine + 1; index < lines.length; index += 1) {
    const line = lines[index].replace(/\r$/, "");
    if (!line.trim()) continue;
    const indentation = line.match(/^\s*/)?.[0].length ?? 0;
    if (indentation <= jobsIndent) {
      jobsEndLine = index;
      break;
    }
    const key = /^\s*([A-Za-z0-9_.-]+)\s*:\s*$/.exec(line);
    if (!key) continue;
    if (jobIndent === null) jobIndent = indentation;
    if (indentation === jobIndent) starts.push({ line: index, id: key[1] });
  }
  return starts.map((start, index) => {
    const endLine = starts[index + 1]?.line ?? jobsEndLine;
    const rangeStart = offsets[start.line];
    const rangeEnd = endLine < offsets.length ? offsets[endLine] : source.length;
    return { id: start.id, start: rangeStart, end: rangeEnd, text: source.slice(rangeStart, rangeEnd) };
  });
}

export function workflowSecuritySignals(file, text) {
  const relative = String(file?.relative ?? "").replace(/\\/g, "/");
  if (!/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(relative)) return [];
  const analysisText = maskYamlComments(text);
  const signals = [];
  const jobRanges = workflowJobRanges(text);
  const jobsStart = jobRanges[0]?.start ?? analysisText.length;
  const globalWorkflow = analysisText.slice(0, jobsStart);
  const pullRequestTarget = /\bpull_request_target\b/.test(globalWorkflow);
  const untrustedExpression = /\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body|review\.body|head_commit\.message|workflow_run\.head_branch)\s*\}\}/gi;
  for (const range of workflowRunRanges(text)) {
    const match = untrustedExpression.exec(range.text);
    untrustedExpression.lastIndex = 0;
    if (!match) continue;
    const job = jobRanges.find(({ start, end }) => start <= range.start && range.start < end);
    const privilegeScope = `${globalWorkflow}\n${job?.text ?? ""}`;
    const privilegedContext = pullRequestTarget
      && (/^\s*permissions\s*:\s*write-all\b/mi.test(privilegeScope)
        || /^\s*(?:contents|actions|packages|pull-requests|issues|id-token)\s*:\s*write\b/mi.test(privilegeScope)
        || /\bsecrets\s*:\s*inherit\b/i.test(job?.text ?? ""));
    signals.push({
      ruleId: "ci-workflow",
      index: range.start + match.index,
      title: "Untrusted GitHub event data is interpolated into a shell step",
      category: "Supply Chain",
      severity: privilegedContext ? "critical" : "high",
      confidence: "high",
      manual: false,
      description: "A pull request, issue, review, comment, commit, or branch value controlled by another user is expanded directly into a run script before the shell parses it.",
      recommendation: "Assign the expression to an env value and pass it to a fixed command as quoted data, or use an action/API that avoids a shell. Never execute fork code with repository secrets or write tokens.",
      evidence: "Untrusted github.event expression -> workflow run shell",
      tags: ["ci", "github-actions", "command-injection", "supply-chain"],
    });
  }

  const actionReferences = new Map();
  const actionReference = /^\s*-?\s*uses\s*:\s*["']?([^\s#"']+)["']?/gmi;
  for (const match of text.matchAll(actionReference)) {
    const reference = match[1];
    if (reference.startsWith("./") || reference.startsWith("docker://")) continue;
    const separator = reference.lastIndexOf("@");
    if (separator <= 0) continue;
    const revision = reference.slice(separator + 1);
    if (/^[a-f0-9]{40}$/i.test(revision)) continue;
    const existing = actionReferences.get(reference);
    if (existing) {
      existing.occurrences += 1;
      continue;
    }
    actionReferences.set(reference, { index: match.index ?? 0, separator, revision, occurrences: 1 });
  }
  for (const [reference, { index, separator, revision, occurrences }] of actionReferences) {
    signals.push({
      ruleId: "ci-workflow",
      index,
      title: "GitHub Action is referenced by a mutable tag or branch",
      category: "Supply Chain",
      severity: "low",
      confidence: "high",
      manual: true,
      description: `${reference.slice(0, separator)} is selected by ${revision}${occurrences > 1 ? ` in ${occurrences} steps` : ""}, which its repository owner can move to different code after review.`,
      recommendation: "Pin the action to a reviewed full commit SHA and use dependency automation to propose traceable SHA updates while retaining the release tag in a comment.",
      evidence: `Mutable action reference: ${reference}`,
      tags: ["ci", "github-actions", "dependency-pinning", "manual-review"],
    });
  }

  const writeAll = /^\s*permissions\s*:\s*write-all\s*(?:#.*)?$/gmi.exec(text);
  if (writeAll) {
    signals.push({
      ruleId: "ci-workflow",
      index: writeAll.index,
      title: "Workflow grants write access to every token scope",
      category: "Supply Chain",
      severity: "high",
      confidence: "high",
      manual: true,
      description: "permissions: write-all gives the workflow token broad repository mutation privileges, increasing the impact of a compromised action or injected command.",
      recommendation: "Set top-level permissions to read-all or {}, then grant only the individual write scopes required by the smallest possible job.",
      evidence: "Workflow token permission: write-all",
      tags: ["ci", "github-actions", "least-privilege", "manual-review"],
    });
  }

  for (const job of jobRanges) {
    const match = /ref\s*:\s*["']?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/i.exec(job.text);
    const privilegedForkCheckout = pullRequestTarget
      && /uses\s*:\s*["']?actions\/checkout@[^\s#"']+/i.test(job.text)
      && match
      && workflowRunRanges(job.text).length > 0;
    if (!privilegedForkCheckout) continue;
    signals.push({
      ruleId: "ci-workflow",
      index: job.start + (match?.index ?? 0),
      title: "Privileged workflow checks out and executes pull-request code",
      category: "Supply Chain",
      severity: "critical",
      confidence: "high",
      manual: true,
      description: "A pull_request_target workflow checks out the contributor-controlled head revision and also contains shell steps. This can run fork code in the trusted base-repository context.",
      recommendation: "Do not check out or execute pull-request code in pull_request_target. Split untrusted build/test work into a permission-minimal pull_request workflow and pass only reviewed artifacts to a separately gated privileged workflow.",
      evidence: "pull_request_target -> checkout of pull_request.head -> workflow run step",
      tags: ["ci", "github-actions", "pwn-request", "supply-chain", "manual-review"],
    });
  }

  return signals.sort((left, right) => left.index - right.index || left.title.localeCompare(right.title));
}

export function jwtValidationSignals(file, text) {
  if (!isLikelyServerSource(file, text)) return [];
  const signals = [];
  const tokens = javascriptTokens(text);
  const namespaces = new Set();
  const verifiers = new Set();
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value === "import") {
      const from = tokens.findIndex((token, at) => at > index && at < index + 30 && token.value === "from");
      if (from < 0 || tokens[from + 1]?.kind !== "string" || tokens[from + 1].value !== "jsonwebtoken") continue;
      const imported = tokens.slice(index + 1, from);
      if (imported[0]?.kind === "word") namespaces.add(imported[0].value);
      for (let part = 0; part < imported.length; part += 1) {
        if (imported[part].value === "*" && imported[part + 1]?.value === "as") namespaces.add(imported[part + 2]?.value);
        if (imported[part].value === "verify") verifiers.add(imported[part + 1]?.value === "as" ? imported[part + 2]?.value : "verify");
      }
    }
    if (["const", "let", "var"].includes(tokens[index].value)
      && tokens[index + 2]?.value === "=" && tokens[index + 3]?.value === "require"
      && tokens[index + 5]?.kind === "string" && tokens[index + 5].value === "jsonwebtoken") {
      namespaces.add(tokens[index + 1].value);
    }
  }
  for (let index = 0; index < tokens.length; index += 1) {
    let opening;
    if (namespaces.has(tokens[index].value) && tokens[index + 1]?.value === "."
      && tokens[index + 2]?.value === "verify" && tokens[index + 3]?.value === "(") opening = index + 3;
    else if (verifiers.has(tokens[index].value) && tokens[index + 1]?.value === "("
      && tokens[index - 1]?.value !== ".") opening = index + 1;
    else continue;
    const options = tokenArguments(tokens, opening)[2];
    if (!options || options[0]?.value !== "{" || closingToken(options, 0) !== options.length - 1) continue;
    const properties = new Map();
    let uncertain = false;
    for (const property of tokenArguments(options, 0)) {
      if (property[0]?.value === "...") { uncertain = true; continue; }
      if (property[1]?.value !== ":") continue;
      properties.set(property[0].value, property.slice(2));
    }
    for (const [name, value] of properties) {
      const expiration = name === "ignoreExpiration" && value.length === 1 && value[0].value === "true";
      const unsigned = name === "algorithms" && value[0]?.value === "["
        && closingToken(value, 0) === value.length - 1
        && tokenArguments(value, 0).some((entry) => entry.length === 1 && entry[0].kind === "string" && entry[0].value === "none");
      if (!expiration && !unsigned) continue;
    signals.push({
      ruleId: "jwt-validation",
      index: value[0].start,
      title: expiration ? "JWT expiration validation is disabled" : "Unsigned JWTs are explicitly accepted",
      category: "Authentication",
      severity: "critical",
      confidence: uncertain ? "medium" : "high",
      manual: uncertain,
      description: expiration
        ? "The JWT verifier is configured to accept expired tokens, extending stolen or revoked session material beyond its intended lifetime."
        : "The JWT verifier allows the none algorithm, so a token may be accepted without a cryptographic signature.",
      recommendation: "Require signature verification with an explicit allowlist of expected asymmetric algorithms, validate issuer and audience, and enforce exp/nbf with only a small documented clock tolerance.",
      evidence: expiration ? "JWT option: ignoreExpiration=true" : "JWT algorithm allowlist includes none",
      tags: ["jwt", "authentication", "signature-validation"],
    });
    }
  }
  return signals;
}

export function lockfileSecuritySignals(file, text) {
  const name = String(file?.name ?? file?.relative?.split("/").at(-1) ?? "").toLowerCase();
  if (!new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]).has(name)) return [];
  const signals = [];
  const insecure = /["']?(?:resolved|tarball)["']?\s*(?::\s*)?["']?http:\/\/(?!(?:localhost|127(?:\.\d+){3}|\[::1\])(?::\d+)?(?:[\/\s"'#]|$))[^\s"']+/gi;
  for (const match of text.matchAll(insecure)) {
    signals.push({
      ruleId: "lockfile-integrity",
      index: match.index ?? 0,
      title: "Lockfile downloads a package over plaintext HTTP",
      category: "Supply Chain",
      severity: "high",
      confidence: "high",
      manual: false,
      description: "The locked artifact is fetched without authenticated transport, allowing a network attacker to replace package contents before installation.",
      recommendation: "Switch the dependency source to an authenticated HTTPS registry or repository, regenerate the lockfile, and verify that the new entry includes integrity metadata.",
      evidence: "Lockfile resolved/tarball URL uses http:// (URL redacted)",
      tags: ["lockfile", "transport", "integrity", "supply-chain"],
    });
  }
  const credentialed = /https?:\/\/[^\s/@:"']+:[^\s/@"']+@[^\s"']+/gi;
  for (const match of text.matchAll(credentialed)) {
    signals.push({
      ruleId: "hardcoded-auth",
      index: match.index ?? 0,
      title: "Lockfile URL contains embedded credentials",
      category: "Authentication",
      severity: "critical",
      confidence: "high",
      manual: false,
      description: "A dependency URL stores credentials in the lockfile, where they can leak through repository history, CI logs, caches, and published source archives.",
      recommendation: "Revoke the exposed credential, remove it from history, use registry-scoped environment authentication, and regenerate the lockfile without URL userinfo.",
      evidence: "Credential-bearing lockfile URL: <redacted>",
      tags: ["lockfile", "credential", "supply-chain"],
    });
  }

  if (name === "package-lock.json" || name === "npm-shrinkwrap.json") {
    let lockfile = null;
    try {
      lockfile = JSON.parse(text);
    } catch {
      // Manifest/lockfile parsing diagnostics are owned by the main dependency
      // scanner. Avoid duplicating a generic syntax finding here.
    }
    const publicRegistryArtifact = (record) => (
      record
      && typeof record === "object"
      && typeof record.resolved === "string"
      && /^https:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com)\//i.test(record.resolved)
      && record.link !== true
    );
    const missingIntegrity = (record) => (
      publicRegistryArtifact(record)
      && !(typeof record.integrity === "string" && record.integrity.trim())
    );
    const unresolved = [];
    if (lockfile?.packages && typeof lockfile.packages === "object" && !Array.isArray(lockfile.packages)) {
      for (const [packagePath, record] of Object.entries(lockfile.packages)) {
        if (packagePath && missingIntegrity(record)) unresolved.push(record.resolved);
      }
    } else if (lockfile?.dependencies && typeof lockfile.dependencies === "object" && !Array.isArray(lockfile.dependencies)) {
      const pending = [lockfile.dependencies];
      while (pending.length > 0) {
        const dependencies = pending.pop();
        for (const record of Object.values(dependencies)) {
          if (!record || typeof record !== "object") continue;
          if (missingIntegrity(record)) unresolved.push(record.resolved);
          if (record.dependencies && typeof record.dependencies === "object" && !Array.isArray(record.dependencies)) {
            pending.push(record.dependencies);
          }
        }
      }
    }
    let searchOffset = 0;
    for (const resolved of unresolved) {
      const serialized = JSON.stringify(resolved);
      const located = text.indexOf(serialized, searchOffset);
      const index = located >= 0 ? located : 0;
      if (located >= 0) searchOffset = located + serialized.length;
      signals.push({
        ruleId: "lockfile-integrity",
        index,
        title: "Registry artifact is not pinned by an integrity digest",
        category: "Supply Chain",
        severity: "medium",
        confidence: "high",
        manual: false,
        description: "A public-registry tarball entry has a resolved URL but no non-empty integrity value, so the lockfile does not independently bind installation to expected package bytes.",
        recommendation: "Regenerate the lockfile with a current trusted package manager, review the resulting registry source, and require a sha512 integrity value before release.",
        evidence: "HTTPS registry artifact has no integrity digest (URL redacted)",
        tags: ["lockfile", "integrity", "supply-chain"],
      });
    }
  }
  return signals;
}

function staticSignal(ruleId, index, input) {
  return { ruleId, index, confidence: "high", manual: false, ...input };
}

/** High-signal container and IaC configuration checks; no repository code runs. */
export function configurationSecuritySignals(file, text) {
  const relative = String(file?.relative ?? "").replace(/\\/g, "/");
  const name = String(file?.name ?? relative.split("/").at(-1) ?? "").toLowerCase();
  const signals = [];
  const dockerfile = /^dockerfile(?:[._-].*)?$/i.test(name);
  const yaml = /\.ya?ml$/i.test(relative);
  const terraform = /\.tf(?:vars)?$/i.test(relative);

  if (dockerfile) {
    const remoteShell = /^\s*RUN\s+[^\r\n]*\b(?:curl|wget)\b[^\r\n]*(?:\\\r?\n[^\r\n]*){0,8}\|\s*(?:(?:\/usr\/bin\/)?env(?:\s+[A-Za-z_][A-Za-z0-9_]*=[^\s]+)*\s+)?(?:\/bin\/)?(?:sh|bash|zsh)\b/gmi;
    for (const match of text.matchAll(remoteShell)) {
      signals.push(staticSignal("container-hardening", match.index ?? 0, {
        title: "Container build executes a remote shell payload",
        category: "Supply Chain",
        severity: "critical",
        description: "A Docker build downloads content and immediately sends it to a shell without a pinned artifact or integrity verification.",
        recommendation: "Download a version-pinned artifact over HTTPS, verify a publisher signature or reviewed cryptographic checksum, and execute a checked-in build step only after verification.",
        evidence: "Dockerfile RUN: remote download -> shell execution",
        tags: ["container", "dockerfile", "remote-code", "supply-chain"],
      }));
    }

    const remoteAdd = /^\s*ADD\s+(?:--[^\s]+\s+)*https?:\/\/[^\s]+/gmi;
    for (const match of text.matchAll(remoteAdd)) {
      if (/--checksum=sha256:[a-f0-9]{64}\b/i.test(match[0])) continue;
      signals.push(staticSignal("container-hardening", match.index ?? 0, {
        title: "Container build fetches a remote ADD source without visible integrity verification",
        category: "Supply Chain",
        severity: "medium",
        confidence: "medium",
        manual: true,
        description: "Dockerfile ADD retrieves a remote artifact during the build, while this instruction does not show a reviewed checksum or signature contract.",
        recommendation: "Fetch a version-pinned artifact in a RUN step, verify its signature or SHA-256 digest, then unpack it explicitly; prefer a trusted package repository when available.",
        evidence: "Dockerfile ADD uses a remote URL (URL redacted)",
        tags: ["container", "dockerfile", "integrity", "manual-review"],
      }));
    }

    const finalStage = Math.max(0, ...[...text.matchAll(/^\s*FROM\s+/gmi)].map((match) => match.index ?? 0));
    const finalUsers = [...text.slice(finalStage).matchAll(/^\s*USER\s+([^\s#]+)/gmi)];
    const finalUser = finalUsers.at(-1);
    if (finalUser && /^(?:0|root)(?::[A-Za-z0-9_.-]+)?$/i.test(finalUser[1])) {
      signals.push(staticSignal("container-hardening", finalStage + (finalUser.index ?? 0), {
        title: "Final container stage explicitly runs as root",
        category: "Security Configuration",
        severity: "high",
        confidence: "high",
        manual: true,
        description: "The last USER instruction in the final image stage selects UID 0/root, increasing the impact of an application or dependency compromise.",
        recommendation: "Create and select a dedicated unprivileged UID/GID in the final stage, grant only required filesystem ownership, and combine this with runtime privilege dropping and a read-only root filesystem.",
        evidence: "Final-stage Dockerfile USER is root/UID 0",
        tags: ["container", "dockerfile", "least-privilege", "manual-review"],
      }));
    }
  }

  const containerYaml = yaml && (
    /^(?:docker-)?compose(?:\.[^.]+)?\.ya?ml$/i.test(name)
    || /^\s*(?:apiVersion|kind)\s*:/mi.test(text) && /^\s*(?:containers|initContainers)\s*:/mi.test(text)
    || /^\s*services\s*:/mi.test(text) && /^\s*image\s*:/mi.test(text)
  );
  if (containerYaml) {
    const privilegedPatterns = [
      { regex: /^\s*privileged\s*:\s*true\s*(?:#.*)?$/gmi, label: "privileged=true" },
      { regex: /^\s*allowPrivilegeEscalation\s*:\s*true\s*(?:#.*)?$/gmi, label: "allowPrivilegeEscalation=true" },
      { regex: /^\s*(?:hostNetwork|hostPID|hostIPC)\s*:\s*true\s*(?:#.*)?$/gmi, label: "host namespace sharing enabled" },
      { regex: /^\s*runAsUser\s*:\s*0\s*(?:#.*)?$/gmi, label: "runAsUser=0" },
      { regex: /\/var\/run\/docker\.sock\s*:/gmi, label: "Docker daemon socket mounted" },
    ];
    for (const pattern of privilegedPatterns) {
      for (const match of text.matchAll(pattern.regex)) {
        signals.push(staticSignal("container-hardening", match.index ?? 0, {
          title: "Container configuration grants a host-level privilege",
          category: "Security Configuration",
          severity: pattern.label === "allowPrivilegeEscalation=true" ? "high" : "critical",
          confidence: "high",
          manual: true,
          description: `${pattern.label} can weaken container isolation and significantly increase the impact of code execution inside the workload.`,
          recommendation: "Remove the host privilege, run as a non-root user, disable privilege escalation, drop all capabilities, and grant back only a documented minimum capability when unavoidable.",
          evidence: `Container privilege setting: ${pattern.label}`,
          tags: ["container", "orchestration", "least-privilege", "manual-review"],
        }));
      }
    }
  }

  if (terraform) {
    const terraformText = maskYamlComments(maskJavaScriptComments(text));
    const exposures = [
      { regex: /\bacl\s*=\s*["']public-(?:read|read-write)["']/gi, label: "public object-storage ACL", severity: "high" },
      { regex: /\bblock_public_(?:acls|policy)\s*=\s*false\b/gi, label: "public-access blocking disabled", severity: "medium" },
      { regex: /\bpublicly_accessible\s*=\s*true\b/gi, label: "publicly accessible managed resource", severity: "high" },
    ];
    for (const exposure of exposures) {
      for (const match of terraformText.matchAll(exposure.regex)) {
        signals.push(staticSignal("iac-exposure", match.index ?? 0, {
          title: "Infrastructure code enables public resource exposure",
          category: "Security Configuration",
          severity: exposure.severity,
          confidence: "medium",
          manual: true,
          description: `The configuration contains ${exposure.label}. Public access may expose data or a management/data service unless other controls reliably restrict it.`,
          recommendation: "Default the resource to private, use private networking or a narrowly scoped identity policy, and verify the effective cloud policy after deployment. Document any intentional public surface and test it continuously.",
          evidence: `IaC exposure setting: ${exposure.label}`,
          tags: ["iac", "terraform", "public-exposure", "manual-review"],
        }));
      }
    }
  }

  return signals.sort((left, right) => left.index - right.index || left.ruleId.localeCompare(right.ruleId));
}
