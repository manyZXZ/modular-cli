import { blankComment, compact, lineAt } from "./text.js";
import { hasAttribute, tags } from "./markup.js";

export function markdownScalar(field) {
  if (!field) return "";
  const value = field.value.trim();
  const quoted = /^(?:"([\s\S]*)"|'([\s\S]*)')$/.exec(value);
  return (quoted ? (quoted[1] ?? quoted[2] ?? "") : value).trim();
}

export function meaningfulMarkdownScalar(field) {
  const value = markdownScalar(field);
  return value.length > 0 && !/^(?:null|undefined|~)$/i.test(value);
}

export function markdownField(analysis, names) {
  for (const name of names) {
    const field = analysis.frontmatter.get(name.toLowerCase());
    if (field) return field;
  }
  return null;
}

function maskMarkdownCode(text, { maskInline = true } = {}) {
  const lines = text.split("\n");
  let fence = null;
  return lines.map((line) => {
    const opening = /^ {0,3}(`{3,}|~{3,})/.exec(line);
    if (!fence && opening) {
      fence = { character: opening[1][0], length: opening[1].length };
      return blankComment(line);
    }
    if (fence) {
      const closing = new RegExp(`^ {0,3}${fence.character}{${fence.length},}\\s*$`).test(line);
      if (closing) fence = null;
      return blankComment(line);
    }
    return maskInline ? line.replace(/(`+)([^`]*?)\1/g, blankComment) : line;
  }).join("\n");
}

function headingText(text) {
  return text.replace(/(`+)([^`]*?)\1/g, (_match, _delimiter, content) => content).trim();
}

export function analyzeMarkdown(text) {
  const lines = text.split(/\r?\n/);
  const bodyLines = [...lines];
  const frontmatter = new Map();
  let hasFrontmatter = false;
  let closingLine = -1;
  if ((lines[0] ?? "").replace(/^\uFEFF/, "").trim() === "---") {
    closingLine = lines.findIndex((line, index) => index > 0 && /^(?:---|\.\.\.)\s*$/.test(line.trim()));
    hasFrontmatter = closingLine > 0;
  }

  if (hasFrontmatter) {
    const stack = [];
    for (let index = 1; index < closingLine; index += 1) {
      const match = /^(\s*)([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*$/.exec(lines[index]);
      if (!match) continue;
      const indent = match[1].replace(/\t/g, "  ").length;
      while (stack.length > 0 && stack.at(-1).indent >= indent) stack.pop();
      const key = [...stack.map((item) => item.key), match[2].toLowerCase()].join(".");
      const field = { key, value: match[3], raw: lines[index].trim(), line: index + 1 };
      frontmatter.set(key, field);
      if (match[3] === "") stack.push({ indent, key: match[2].toLowerCase() });
    }
    for (let index = 0; index <= closingLine; index += 1) bodyLines[index] = blankComment(bodyLines[index]);
  }

  const contentBody = bodyLines.join("\n");
  const body = maskMarkdownCode(contentBody);
  // A code span contributes visible heading text. Recognize heading markers
  // before removing its delimiters so a standalone `# example` stays code.
  const bodyRows = maskMarkdownCode(contentBody, { maskInline: false }).split("\n");
  const headings = [];
  for (let index = 0; index < bodyRows.length; index += 1) {
    const line = bodyRows[index];
    const atx = /^ {0,3}(#{1,6})(?:[\t ]+(.*?))?[\t ]*$/.exec(line);
    if (atx) {
      const content = headingText((atx[2] ?? "").replace(/[\t ]+#+[\t ]*$/, ""));
      headings.push({ level: atx[1].length, content, raw: lines[index] ?? line, line: index + 1 });
      continue;
    }
    if (index + 1 < bodyRows.length && line.trim()) {
      const setext = /^ {0,3}(=+|-+)[\t ]*$/.exec(bodyRows[index + 1]);
      if (setext) {
        headings.push({
          level: setext[1][0] === "=" ? 1 : 2,
          content: headingText(line),
          raw: `${lines[index] ?? line}\n${lines[index + 1] ?? bodyRows[index + 1]}`,
          line: index + 1,
        });
        index += 1;
      }
    }
  }

  return { body, frontmatter, hasFrontmatter, headings };
}

export function auditMarkdown(context, analysis, add) {
  const { file } = context;
  const title = markdownField(analysis, ["title", "seo.title"]);
  const description = markdownField(analysis, ["description", "seo.description", "meta.description"]);
  const canonical = markdownField(analysis, ["canonical", "canonicalurl", "canonical_url", "seo.canonical", "seo.canonicalurl"]);
  const nonEmptyH1 = analysis.headings.find((heading) => heading.level === 1 && heading.content);

  if (title && !meaningfulMarkdownScalar(title)) {
    add({
      id: "seo-markdown-empty-title",
      title: "Markdown frontmatter has an empty title",
      category: "SEO",
      severity: "medium",
      description: "An empty content title weakens route metadata, page hierarchy, link previews, and answer-engine context.",
      evidence: title.raw,
      file: file.relative,
      line: title.line,
      recommendation: "Provide a concise, route-specific frontmatter title, or remove the empty field and supply one unambiguous level-one heading that the site generator uses as its title.",
      suggestedFiles: [file.relative],
      tags: ["seo", "aeo", "content-hierarchy"],
    });
  }
  if (!meaningfulMarkdownScalar(title) && !nonEmptyH1) {
    add({
      id: "content-missing-h1",
      title: "Markdown page has no usable title or level-one heading",
      category: "Content hierarchy",
      severity: "medium",
      confidence: "medium",
      description: "A content page needs one clear primary topic for readers, search systems, and assistive technology.",
      evidence: "No non-empty frontmatter `title` or Markdown H1 was found.",
      file: file.relative,
      line: 1,
      recommendation: "Add a meaningful frontmatter `title` or one visible `#` heading, following the site's layout convention so the rendered page does not duplicate it.",
      suggestedFiles: [file.relative],
      tags: ["seo", "aeo", "screen-reader", "content-hierarchy"],
    });
  }

  if (description && !meaningfulMarkdownScalar(description)) {
    add({
      id: "seo-markdown-empty-description",
      title: "Markdown frontmatter has an empty description",
      category: "SEO",
      severity: "medium",
      description: "An explicitly empty description cannot summarize the page for search or sharing metadata.",
      evidence: description.raw,
      file: file.relative,
      line: description.line,
      recommendation: "Write a truthful route-specific description, or remove this empty field only if the build reliably derives an equivalent excerpt.",
      suggestedFiles: [file.relative],
      tags: ["seo", "conversion", "scannability"],
    });
  } else if (analysis.hasFrontmatter && meaningfulMarkdownScalar(title) && !description) {
    add({
      id: "seo-markdown-missing-description",
      title: "Markdown content metadata has no explicit description",
      category: "SEO",
      severity: "low",
      confidence: "medium",
      manual: true,
      description: "The build may derive an excerpt, but source analysis cannot verify that it is route-specific or suitable for search snippets.",
      evidence: "Frontmatter contains a title but no `description` field.",
      file: file.relative,
      line: title.line,
      recommendation: "Confirm the generated metadata; add a concise frontmatter description when the framework does not reliably derive and sanitize a useful excerpt.",
      suggestedFiles: [file.relative],
      tags: ["seo", "content", "conversion"],
    });
  }

  if (canonical && !meaningfulMarkdownScalar(canonical)) {
    add({
      id: "seo-markdown-empty-canonical",
      title: "Markdown frontmatter has an empty canonical URL",
      category: "SEO",
      severity: "low",
      description: "An empty canonical field can render invalid metadata or override a correct layout default.",
      evidence: canonical.raw,
      file: file.relative,
      line: canonical.line,
      recommendation: "Set the production canonical URL or remove the empty override so a verified layout-level canonical can be emitted.",
      suggestedFiles: [file.relative],
      tags: ["seo", "canonical", "duplicate-content"],
    });
  }

  const robots = markdownField(analysis, ["robots", "seo.robots"]);
  const noindex = markdownField(analysis, ["noindex", "seo.noindex"]);
  const robotsIndex = markdownField(analysis, ["robots.index", "seo.robots.index"]);
  let noindexEvidence = null;
  if (/^(?:true|yes|on|1)$/i.test(markdownScalar(noindex))) noindexEvidence = noindex;
  else if (/\bnoindex\b|\bindex\s*:\s*false\b/i.test(markdownScalar(robots))) noindexEvidence = robots;
  else if (/^(?:false|no|off|0)$/i.test(markdownScalar(robotsIndex))) noindexEvidence = robotsIndex;
  if (noindexEvidence) {
    add({
      id: "seo-page-noindex",
      title: "Markdown frontmatter excludes this content from indexing",
      category: "SEO",
      severity: "medium",
      confidence: "medium",
      description: "A noindex directive removes the generated page from conventional search and can reduce answer-engine discoverability.",
      evidence: noindexEvidence.raw,
      file: file.relative,
      line: noindexEvidence.line,
      recommendation: "Confirm this content should remain private, draft, or temporary; otherwise remove the noindex directive before production.",
      suggestedFiles: [file.relative],
      tags: ["seo", "geo", "aeo", "indexability"],
    });
  }

  for (const heading of analysis.headings) {
    if (heading.content) continue;
    add({
      id: "content-empty-heading",
      title: "Markdown heading has no readable content",
      category: "Content hierarchy",
      severity: "medium",
      description: "An empty heading creates a meaningless outline stop and no scannable description for the following section.",
      evidence: heading.raw,
      file: file.relative,
      line: heading.line,
      recommendation: "Remove the marker or add concise heading text that describes the section that follows.",
      suggestedFiles: [file.relative],
      tags: ["screen-reader", "readability", "content-hierarchy"],
    });
  }
  const h1s = analysis.headings.filter((heading) => heading.level === 1 && heading.content);
  if (h1s.length > 1) {
    add({
      id: "content-multiple-h1",
      title: "Markdown page has multiple level-one headings",
      category: "Content hierarchy",
      severity: "low",
      confidence: "medium",
      manual: true,
      description: "Multiple H1s can be intentional, but generated content pages normally need one unambiguous primary topic.",
      evidence: `${h1s.length} level-one headings were found; the second is “${compact(h1s[1].content, 80)}”.`,
      file: file.relative,
      line: h1s[1].line,
      recommendation: "Confirm the rendered outline and demote secondary top-level headings when they are subsections of the page topic.",
      suggestedFiles: [file.relative],
      tags: ["seo", "aeo", "screen-reader", "content-hierarchy"],
    });
  }
  const headingJump = analysis.headings.find((heading, index) => index > 0
    && heading.level > analysis.headings[index - 1].level + 1);
  if (headingJump) {
    add({
      id: "content-heading-jump",
      title: "Markdown heading hierarchy skips a level",
      category: "Content hierarchy",
      severity: "low",
      description: "Skipped levels can make long-form content harder to scan and navigate with assistive technology.",
      evidence: headingJump.raw,
      file: file.relative,
      line: headingJump.line,
      recommendation: "Use heading levels to represent a nested outline rather than visual size.",
      suggestedFiles: [file.relative],
      tags: ["readability", "scannability", "screen-reader"],
    });
  }

  const imagePatterns = [
    /!\[([^\]\r\n]*)\]\(\s*(<?[^)\s>]+>?)[^)\r\n]*\)/g,
    /!\[([^\]\r\n]*)\]\[[^\]\r\n]*\]/g,
  ];
  for (const pattern of imagePatterns) {
    for (const image of analysis.body.matchAll(pattern)) {
      if (image[1].trim()) continue;
      add({
        id: "a11y-markdown-image-alt-review",
        title: "Markdown image has empty alternative text",
        category: "Accessibility",
        severity: "low",
        confidence: "medium",
        manual: true,
        description: "Empty alt text is correct only when the image is decorative and conveys no information or function.",
        evidence: compact(image[0]),
        file: file.relative,
        line: lineAt(analysis.body, image.index ?? 0),
        recommendation: "Keep empty alt text for a genuinely decorative image; otherwise describe the image's relevant meaning concisely inside `![...]`.",
        suggestedFiles: [file.relative],
        tags: ["images", "screen-reader", "content"],
      });
    }
  }

  const linkPattern = /(?<!!)\[([^\]\r\n]*)\]\(\s*(<?[^)\s>]+>?)[^)\r\n]*\)/g;
  for (const link of analysis.body.matchAll(linkPattern)) {
    const label = link[1].replace(/[*_~`]/g, "").trim();
    const destination = link[2].replace(/^<|>$/g, "");
    if (!label) {
      add({
        id: "a11y-link-name",
        title: "Markdown link has no accessible name",
        category: "Accessibility",
        severity: "high",
        description: "An empty link cannot communicate its destination or purpose to readers or assistive technology.",
        evidence: compact(link[0]),
        file: file.relative,
        line: lineAt(analysis.body, link.index ?? 0),
        recommendation: "Add concise link text that makes sense out of context.",
        suggestedFiles: [file.relative],
        tags: ["navigation", "screen-reader", "seo"],
      });
    } else if (/^(?:click here|here|read more|learn more|buraya tıkla|tıkla|devamı)$/i.test(label)) {
      add({
        id: "ux-ambiguous-link-text",
        title: "Markdown link text is ambiguous out of context",
        category: "Usability",
        severity: "low",
        description: "Generic link labels are difficult to scan and unhelpful in a screen reader's links list.",
        evidence: compact(link[0]),
        file: file.relative,
        line: lineAt(analysis.body, link.index ?? 0),
        recommendation: "Replace generic text with a concise description of the destination or action.",
        suggestedFiles: [file.relative],
        tags: ["scannability", "navigation", "screen-reader"],
      });
    }
    if (/^http:\/\/(?!localhost\b|127\.0\.0\.1\b)/i.test(destination)) {
      add({
        id: "security-insecure-resource",
        title: "Markdown link uses an insecure HTTP URL",
        category: "Security & privacy",
        severity: "high",
        description: "HTTP destinations can be intercepted and weaken user trust when linked from a secure site.",
        evidence: compact(link[0]),
        file: file.relative,
        line: lineAt(analysis.body, link.index ?? 0),
        recommendation: "Use the destination's verified HTTPS URL, or remove the link if no secure endpoint exists.",
        suggestedFiles: [file.relative],
        tags: ["transport-security", "privacy", "trust"],
      });
    }
  }

  for (const image of tags(analysis.body, "img")) {
    if (hasAttribute(image.raw, "alt")) continue;
    add({
      id: "a11y-image-alt",
      title: "HTML image inside Markdown is missing alternative text",
      category: "Accessibility",
      severity: "high",
      description: "An image without `alt` is not reliably understandable to screen-reader users.",
      evidence: image.raw,
      file: file.relative,
      line: lineAt(analysis.body, image.index),
      recommendation: "Add concise meaningful `alt` text, or `alt=\"\"` when the image is purely decorative.",
      suggestedFiles: [file.relative],
      tags: ["screen-reader", "images", "wcag"],
    });
  }
}
