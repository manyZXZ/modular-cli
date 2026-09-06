import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { collectFiles } from "../src/core/files.js";
import { runSecurityScan } from "../src/scanners/security.js";

export async function measureSecurityAccuracy() {
  const corpus = JSON.parse(await fs.readFile(new URL("../test/fixtures/security-accuracy.json", import.meta.url), "utf8"));
  const originals = corpus.cases;
  const cases = [...originals, ...originals.filter(({ partition }) => partition === "regression").map((entry) => ({
    ...entry, id: `${entry.id}/renamed-and-shifted`, partition: "metamorphic",
    code: `// Source offsets and identifier spelling must not determine safety.\n\n${entry.code.replace(/\btarget\b/g, "destinationValue")}`,
  }))];
  const temp = await fs.realpath(os.tmpdir());
  const root = await fs.mkdtemp(path.join(temp, "modular-accuracy-"));
  try {
    await fs.mkdir(path.join(root, "server"));
    await fs.writeFile(path.join(root, "index.html"), "<!doctype html><html><head><title>Fixture</title></head><body><main>Fixture</main></body></html>");
    for (const [index, entry] of cases.entries()) {
      entry.file = `server/case-${index}.js`;
      await fs.writeFile(path.join(root, entry.file), entry.code);
    }
    const result = await runSecurityScan({ root, ...await collectFiles(root) });
    const observed = result.metadata.findingIndex ?? result.findings;
    const groups = new Map();
    const mismatches = [];
    for (const entry of cases) {
      const actual = observed.filter((finding) => finding.file === entry.file && finding.id === entry.rule).length;
      const key = `${entry.partition}/${entry.framework}/${entry.rule}`;
      const group = groups.get(key) ?? { group: key, cases: 0, tp: 0, fp: 0, fn: 0, tn: 0 };
      group.cases += 1;
      group.tp += Math.min(entry.expected, actual);
      group.fp += Math.max(0, actual - entry.expected);
      group.fn += Math.max(0, entry.expected - actual);
      group.tn += entry.expected === 0 && actual === 0 ? 1 : 0;
      groups.set(key, group);
      if (actual !== entry.expected) mismatches.push({ id: entry.id, expected: entry.expected, actual });
    }
    return {
      scope: "Labeled synthetic regression, validation and metamorphic cases; not population accuracy or security certification.",
      cases: cases.length,
      groups: [...groups.values()].map((group) => ({ ...group,
        precision: group.tp + group.fp ? group.tp / (group.tp + group.fp) : null,
        recall: group.tp + group.fn ? group.tp / (group.tp + group.fn) : null,
      })),
      mismatches,
    };
  } finally {
    const real = await fs.realpath(root);
    if (path.dirname(real).toLowerCase() !== temp.toLowerCase() || !path.basename(real).startsWith("modular-accuracy-")) {
      throw new Error("Refusing cleanup outside the accuracy fixture.");
    }
    await fs.rm(real, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await measureSecurityAccuracy();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.mismatches.length) process.exitCode = 1;
}
