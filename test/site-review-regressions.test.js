import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { collectFiles } from "../src/core/files.js";
import { runSiteScan } from "../src/scanners/mysite.js";

async function scanFixture(t, entries) {
  const parent = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(parent, "modular-site-review-"));
  t.after(async () => {
    const resolved = await fs.realpath(root);
    assert.equal(path.dirname(resolved).toLowerCase(), parent.toLowerCase());
    assert.ok(path.basename(resolved).startsWith("modular-site-review-"));
    await fs.rm(resolved, { recursive: true, force: true });
  });
  for (const [relative, value] of Object.entries(entries)) {
    const destination = path.join(root, relative);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, typeof value === "string" ? value : JSON.stringify(value));
  }
  const inventory = await collectFiles(root);
  return runSiteScan({ root, ...inventory, options: { includeManualReviews: false } });
}

const astroEntries = {
  "package.json": { private: true, dependencies: { astro: "5.0.0" } },
  "src/pages/index.astro": "<main><h1>Home</h1></main>",
};

test("collector and website scanner audit the same Markdown pages in root and nested Astro apps", async (t) => {
  const brokenContent = '---\ntitle: ""\ndescription: ""\n---\n#\n[](http://example.test/guide)\n';
  const entries = {
    ...astroEntries,
    "src/content/post.md": brokenContent,
    "src/content/docs/reference.mdx": brokenContent,
    "src/pages/tutorial.mdx": brokenContent,
    "README.md": brokenContent,
    "docs/guide.md": brokenContent,
    "docs/site/package.json": astroEntries["package.json"],
    "docs/site/src/content/example.md": brokenContent,
    "fixtures/site/package.json": astroEntries["package.json"],
    "fixtures/site/src/content/example.md": brokenContent,
    "src/content/fixtures/example.md": brokenContent,
  };
  const prefix = "apps/blog/";
  const rootResult = await scanFixture(t, entries);
  const nestedResult = await scanFixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"] },
    ...Object.fromEntries(Object.entries(entries).map(([relative, value]) => [`${prefix}${relative}`, value])),
  });

  const contentFiles = ["src/content/post.md", "src/content/docs/reference.mdx", "src/pages/tutorial.mdx"];
  for (const [result, localPrefix] of [[rootResult, ""], [nestedResult, prefix]]) {
    assert.equal(result.metadata.scope.markdownFiles, contentFiles.length);
    for (const file of contentFiles) {
      assert.ok(result.findings.some((finding) => finding.file === `${localPrefix}${file}`
        && finding.id === "seo-markdown-empty-title" && finding.line === 2), file);
      assert.ok(result.findings.some((finding) => finding.file === `${localPrefix}${file}`
        && finding.id === "security-insecure-resource" && finding.line === 6), file);
    }
    assert.ok(result.findings.every(({ file }) => !file?.endsWith("README.md")
      && !file?.includes("/example.md") && !file?.endsWith("docs/guide.md")));
  }
  const contentFindings = (result, localPrefix) => result.findings
    .filter(({ file }) => contentFiles.some((relative) => file === `${localPrefix}${relative}`))
    .map(({ id, file, line, severity }) => ({ id, file: file.slice(localPrefix.length), line, severity }));
  assert.deepEqual(contentFindings(nestedResult, prefix), contentFindings(rootResult, ""));
});

test("website scan resolves static JSX language strings and leaves runtime expressions unproven", async (t) => {
  const validOrDynamic = [
    'lang="en"',
    'lang={"en"}',
    "lang={'tr-TR'}",
    'lang={`en-US`}',
    'lang={ "zh-Hant" }',
    String.raw`lang={"\u0065n"}`,
    String.raw`lang={"\u{65}n"}`,
    'lang={locale}',
    'lang={settings.locale}',
    'lang={isTurkish ? "tr" : "en"}',
    'lang={`en-${region}`}',
    'lang={"en" + suffix}',
  ];
  const invalid = [
    "",
    'lang=""',
    'lang={""}',
    "lang={''}",
    'lang={``}',
    'lang={"   "}',
    'lang={"en_US"}',
    'lang={"English Language"}',
    'lang={"$"}',
    'lang={"${region}"}',
    'lang={`en_US`}',
    'lang={null}',
    'lang={undefined}',
    'lang={false}',
    'lang={42}',
  ];
  const entries = { "package.json": { private: true, dependencies: { next: "15.0.0" } } };
  for (const [group, cases] of [["accepted", validOrDynamic], ["invalid", invalid]]) {
    cases.forEach((attribute, index) => {
      entries[`app/${group}-${index}/layout.tsx`] = `export default function Layout() { return <html ${attribute}><body><main><h1>Page</h1></main></body></html>; }`;
    });
  }
  const result = await scanFixture(t, entries);
  const languageFindings = result.findings.filter(({ id }) => id === "a11y-document-language");
  assert.equal(languageFindings.length, invalid.length);
  assert.ok(languageFindings.every(({ file }) => file.startsWith("app/invalid-")));
  invalid.forEach((attribute, index) => assert.ok(languageFindings.some(({ file }) => file === `app/invalid-${index}/layout.tsx`), attribute));
});

test("inline code supplies visible ATX and setext heading text without exposing code-example links", async (t) => {
  const result = await scanFixture(t, {
    ...astroEntries,
    "src/content/atx.md": [
      "# `useState`",
      "## `setState`",
      "`# This is code, not another heading`",
      "`[](http://example.test/code-only)`",
      "`![](code-only.png)`",
      "`<img src=\"code-only.png\">`",
      "```md",
      "# Fenced heading",
      "[](http://example.test/fenced-only)",
      "```",
    ].join("\n"),
    "src/content/setext.md": "`useReducer`\n============\n\nAPI reference.\n",
  });
  const unexpected = new Set([
    "content-missing-h1", "content-empty-heading", "content-multiple-h1", "content-heading-jump",
    "a11y-link-name", "security-insecure-resource", "a11y-markdown-image-alt-review", "a11y-image-alt",
  ]);
  assert.ok(result.findings.every(({ id, file }) => !file?.startsWith("src/content/") || !unexpected.has(id)),
    JSON.stringify(result.findings.filter(({ id, file }) => file?.startsWith("src/content/") && unexpected.has(id))));
});

test("Markdown code masking retains outside-code findings and their original lines", async (t) => {
  const result = await scanFixture(t, {
    ...astroEntries,
    "src/content/reference.md": [
      "# `useState`",
      "`[](http://example.test/code-only)`",
      "`![](code-only.png)`",
      "[](http://example.test/actual-link)",
      "![](actual-image.png)",
    ].join("\n"),
  });
  const findings = result.findings.filter(({ file }) => file === "src/content/reference.md");
  for (const [id, line] of [["a11y-link-name", 4], ["security-insecure-resource", 4], ["a11y-markdown-image-alt-review", 5]]) {
    assert.deepEqual(findings.filter((finding) => finding.id === id).map((finding) => finding.line), [line], id);
  }
});

test("blank Markdown headings and fenced-only titles remain actionable", async (t) => {
  const result = await scanFixture(t, {
    ...astroEntries,
    "src/content/blank.md": "# ` `\n",
    "src/content/fenced.md": "```md\n# Example title\n```\n",
  });
  assert.ok(result.findings.some(({ file, id }) => file === "src/content/blank.md" && id === "content-empty-heading"));
  for (const expected of ["src/content/blank.md", "src/content/fenced.md"]) {
    assert.ok(result.findings.some(({ file, id }) => file === expected && id === "content-missing-h1"), expected);
  }
});
