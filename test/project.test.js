import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  collectFiles,
  isWebAssetFile,
  verifyFileMetadata,
} from "../src/core/files.js";
import { detectWebProject } from "../src/core/project.js";

async function makeFixture(t, entries) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));

  for (const [relative, contents] of Object.entries(entries)) {
    const destination = path.join(root, relative);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.writeFile(destination, typeof contents === "string" ? contents : JSON.stringify(contents, null, 2));
  }

  const { files } = await collectFiles(root);
  return { root, files };
}

test("accepts a valid static website entry without package metadata", async (t) => {
  const project = await makeFixture(t, {
    "index.html": "<!doctype html><html><head><title>Home</title></head><body><main>Hello</main></body></html>",
    "styles.css": "body { color: #111; }",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, null);
  assert.ok(result.confidence >= 0.7);
  assert.ok(result.signals.includes("entry:valid-index-html"));
});

test("accepts a valid index.htm static website entry", async (t) => {
  const project = await makeFixture(t, {
    "index.htm": "<!doctype html><html><head><title>Home</title></head><body><main>Real site</main></body></html>",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.ok(result.signals.includes("entry:valid-index-html"));
});

test("does not mistake a stray HTML document for a website", async (t) => {
  const project = await makeFixture(t, {
    "docs/example.html": "<!doctype html><html><body><article>API example</article></body></html>",
    "src/math.js": "export const add = (a, b) => a + b;",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.ok(result.reasons.some((reason) => /No framework|runnable website/i.test(reason)));
  assert.ok(result.confidence < 0.58);
});

test("does not bypass bounded project detection with an oversized root manifest", async (t) => {
  const oversizedManifest = `${JSON.stringify({
    private: true,
    scripts: { dev: "next dev" },
    dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
  })}${" ".repeat(1_600_000)}`;
  const project = await makeFixture(t, {
    "package.json": oversizedManifest,
    "next.config.mjs": "export default {};",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.ok(!result.signals.includes("package:web-script"));
});

const applicationFrameworks = [
  ["Next.js", { dependencies: { next: "latest", react: "latest", "react-dom": "latest" } }, "next.config.mjs"],
  ["Nuxt", { dependencies: { nuxt: "latest" } }, "nuxt.config.ts"],
  ["Astro", { dependencies: { astro: "latest" } }, "astro.config.mjs"],
  ["Gatsby", { dependencies: { gatsby: "latest" } }, "gatsby-config.js"],
  ["Remix", { dependencies: { "@remix-run/react": "latest" } }, "remix.config.js"],
  ["SvelteKit", { devDependencies: { "@sveltejs/kit": "latest", svelte: "latest" } }, "svelte.config.js"],
];

for (const [name, manifest, config] of applicationFrameworks) {
  test(`accepts a ${name} application`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": { private: true, scripts: { dev: name === "Gatsby" ? "gatsby develop" : "vite dev" }, ...manifest },
      [config]: "export default {};",
    });

    const result = await detectWebProject(project);

    assert.equal(result.isWebsite, true);
    assert.equal(result.framework, name);
    assert.ok(result.confidence >= 0.68);
  });
}

test("accepts an Angular browser application workspace", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      scripts: { start: "ng serve" },
      dependencies: { "@angular/core": "latest", "@angular/platform-browser": "latest" },
    },
    "angular.json": { projects: { site: { projectType: "application" } } },
    "src/app/app.component.ts": "export class AppComponent {}",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Angular");
});

const clientFrameworks = [
  ["React", { react: "latest", "react-dom": "latest" }, "src/App.jsx", "export function App() { return <main>Hello</main>; }"],
  ["Vue", { vue: "latest" }, "src/App.vue", "<template><main>Hello</main></template>"],
  ["Svelte", { svelte: "latest" }, "src/App.svelte", "<main>Hello</main>"],
];

for (const [name, dependencies, sourcePath, source] of clientFrameworks) {
  test(`accepts a ${name} client application`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": { private: true, scripts: { dev: "vite" }, dependencies, devDependencies: { vite: "latest" } },
      "vite.config.js": "export default {};",
      [sourcePath]: source,
      "src/main.js": "document.getElementById('app');",
    });

    const result = await detectWebProject(project);

    assert.equal(result.isWebsite, true);
    assert.equal(result.framework, name);
    assert.ok(result.signals.includes("package:web-script"));
  });
}

test("accepts a vanilla Vite website", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, scripts: { dev: "vite", build: "vite build" }, devDependencies: { vite: "latest" } },
    "vite.config.js": "export default {};",
    "src/main.js": "document.querySelector('#app').textContent = 'Hello';",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Vite");
});

test("finds a Vite DOM entry after more than thirty alphabetically earlier source files", async (t) => {
  const earlierSources = Object.fromEntries(
    Array.from({ length: 35 }, (_, index) => [
      `src/a-${String(index).padStart(2, "0")}.js`,
      `export const value${index} = ${index};`,
    ]),
  );
  const project = await makeFixture(t, {
    "package.json": { private: true, scripts: { dev: "vite" }, devDependencies: { vite: "latest" } },
    "vite.config.js": "export default {};",
    ...earlierSources,
    "src/main.js": "document.querySelector('#app').textContent = 'Hello';",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Vite");
  assert.ok(result.signals.includes("source:browser-dom"));
});

test("rejects a backend-only Node repository", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { scripts: { start: "node src/server.js" }, dependencies: { express: "latest" } },
    "src/server.js": "import express from 'express'; const app = express(); app.listen(3000);",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, null);
  assert.ok(result.signals.includes("runtime:backend-only"));
});

test("rejects a generic Node CLI even when it has HTML documentation", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { bin: { example: "bin/example.js" }, dependencies: { commander: "latest" } },
    "bin/example.js": "#!/usr/bin/env node\nconsole.log('hello');",
    "docs/usage.html": "<!doctype html><html><body><main>CLI usage</main></body></html>",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("package:cli"));
});

test("rejects a backend CLI whose test fixture contains a complete framework app", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      bin: { api: "src/server.js" },
      dependencies: { express: "latest" },
    },
    "src/server.js": "import express from 'express'; express().listen(3000);",
    "test/fixtures/package.json": {
      private: true,
      scripts: { dev: "next dev" },
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "test/fixtures/app/page.tsx": "export default () => <main>Fixture</main>;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("package:cli"));
  assert.ok(result.signals.includes("runtime:backend-only"));
});

test("rejects a publishable React component library", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      exports: { ".": "./dist/index.js" },
      scripts: { build: "vite build" },
      peerDependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "vite.config.ts": "export default {};",
    "src/Button.tsx": "export const Button = () => <button>Click</button>;",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, "React");
  assert.ok(result.signals.includes("package:library"));
});

test("rejects a publishable browser widget whose mount API uses the DOM", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      main: "./dist/index.js",
      exports: { ".": "./dist/index.js" },
      scripts: { build: "vite build" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "vite.config.ts": "export default {};",
    "src/index.tsx": [
      "export function mount(target) {",
      "  const element = document.createElement('div');",
      "  target.appendChild(element);",
      "  return element;",
      "}",
    ].join("\n"),
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, "React");
  assert.ok(result.signals.includes("source:browser-dom"));
  assert.ok(result.signals.includes("package:library"));
});

for (const container of ["example", "examples", "demo", "demos"]) {
  test(`rejects a publishable UI library whose only Next.js app is under ${container}/`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": {
        exports: { ".": "./dist/index.js" },
        peerDependencies: { react: "latest", "react-dom": "latest" },
      },
      "src/Button.tsx": "export const Button = () => <button>Click</button>;",
      [`${container}/showcase/package.json`]: {
        private: true,
        scripts: { dev: "next dev" },
        dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
      },
      [`${container}/showcase/next.config.mjs`]: "export default {};",
      [`${container}/showcase/app/page.tsx`]: "export default function Page() { return <main>Example</main>; }",
    });

    const result = await detectWebProject(project);
    assert.equal(result.isWebsite, false);
    assert.ok(result.signals.includes("package:library"));
    assert.ok(!result.signals.includes("source:web-routes"));
  });
}

for (const extension of ["ts", "mts", "cts"]) {
  test(`rejects private Vite library mode from a .${extension} config`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": {
        private: true,
        scripts: { build: "vite build" },
        dependencies: { react: "latest", "react-dom": "latest" },
        devDependencies: { vite: "latest" },
      },
      [`vite.config.${extension}`]: "export default { build: { lib: { entry: 'src/index.tsx', formats: ['es'] } } };",
      "src/index.tsx": "export { Button } from './Button.js';",
      "src/Button.tsx": "export const Button = () => <button>Click</button>;",
    });

    const result = await detectWebProject(project);
    assert.equal(result.isWebsite, false);
    assert.equal(result.framework, "React");
    assert.ok(result.signals.includes("tooling:vite-library-mode"));
  });
}

test("finds Vite library mode after more than twenty alphabetically earlier configs", async (t) => {
  const earlierConfigs = Object.fromEntries(
    Array.from({ length: 25 }, (_, index) => [
      `a-${String(index).padStart(2, "0")}/vite.config.ts`,
      "export default {};",
    ]),
  );
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      scripts: { build: "vite build" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    ...earlierConfigs,
    "vite.config.ts": "export default { build: { lib: { entry: 'src/main.tsx' } } };",
    "src/main.tsx": "document.querySelector('#preview'); export const Button = () => <button>Click</button>;",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("tooling:vite-library-mode"));
});

test("preserves real routes named demo and examples", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, dependencies: { react: "latest", "react-dom": "latest" } },
    "app/demo/page.tsx": "export default function Demo() { return <main>Demo</main>; }",
    "pages/examples/index.tsx": "export default function Examples() { return <main>Examples</main>; }",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, true);
  assert.ok(result.signals.includes("source:web-routes"));
});

for (const segment of ["docs", "test", "generated", "demo", "examples"]) {
  test(`preserves a production workspace route named ${segment}`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": { private: true, workspaces: ["apps/*"] },
      "apps/web/package.json": {
        private: true,
        dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
      },
      [`apps/web/app/${segment}/page.tsx`]: `export default function Page() { return <main>${segment}</main>; }`,
    });

    const result = await detectWebProject(project);

    assert.equal(result.isWebsite, true);
    assert.equal(result.framework, "Next.js");
    assert.ok(result.signals.includes("source:web-routes"));
  });
}

test("preserves a website application under an apps/web monorepo path", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"] },
    "apps/web/package.json": {
      private: true,
      scripts: { dev: "next dev" },
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "apps/web/next.config.mjs": "export default {};",
    "apps/web/app/page.tsx": "export default function Page() { return <main>Web app</main>; }",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Next.js");
  assert.ok(result.signals.includes("source:web-routes"));
});

test("accepts a vanilla Vite application inside an apps/web workspace", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, workspaces: ["apps/*"] },
    "apps/web/package.json": {
      private: true,
      scripts: { dev: "vite", build: "vite build" },
      devDependencies: { vite: "latest" },
    },
    "apps/web/vite.config.ts": "export default {};",
    "apps/web/index.html": "<!doctype html><html><body><main id=\"app\"></main><script type=\"module\" src=\"/src/main.ts\"></script></body></html>",
    "apps/web/src/main.ts": "document.querySelector('#app').textContent = 'Web app';",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Vite");
  assert.ok(result.signals.includes("entry:valid-index-html"));
  assert.ok(result.signals.includes("source:client-entry"));
});

test("finds a website workspace manifest after more than forty alphabetically earlier manifests", async (t) => {
  const earlierManifests = Object.fromEntries(
    Array.from({ length: 45 }, (_, index) => [
      `aaa-${String(index).padStart(2, "0")}/package.json`,
      { private: true, name: `utility-${index}` },
    ]),
  );
  const project = await makeFixture(t, {
    "package.json": { private: true, workspaces: ["apps/*", "aaa-*"] },
    ...earlierManifests,
    "apps/web/package.json": {
      private: true,
      scripts: { dev: "next dev" },
      dependencies: { next: "latest", react: "latest", "react-dom": "latest" },
    },
    "apps/web/next.config.mjs": "export default {};",
    "apps/web/app/page.tsx": "export default function Page() { return <main>Web app</main>; }",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Next.js");
  assert.ok(result.signals.includes("framework:next.js"));
});

test("rejects a Next.js peer library with no runnable application", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: false,
      main: "./dist/index.js",
      exports: { ".": "./dist/index.js" },
      peerDependencies: { next: "latest" },
    },
    "src/index.js": "export function withExample(config) { return config; }",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, "Next.js");
  assert.ok(result.signals.includes("framework-peer:next.js"));
  assert.ok(result.signals.includes("package:library"));
  assert.ok(result.confidence < 0.58);
});

test("rejects a private Next.js tooling package with no runnable entry", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, dependencies: { next: "latest" } },
    "src/helper.js": "export const configure = (value) => value;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, "Next.js");
});

test("rejects a private Vite-powered React component library without an app entry", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      scripts: { build: "vite build" },
      dependencies: { react: "latest", "react-dom": "latest", vite: "latest" },
    },
    "vite.config.ts": "export default { build: { lib: { entry: 'src/Button.tsx' } } };",
    "src/Button.tsx": "export const Button = () => <button>Click</button>;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.equal(result.framework, "React");
});

test("rejects a private exported browser widget without a page or route", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      exports: "./src/index.tsx",
      dependencies: { react: "latest", "react-dom": "latest" },
    },
    "src/index.tsx": "document.querySelector('#mount'); export const Widget = () => <button>Widget</button>;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("package:library"));
  assert.ok(!result.signals.includes("source:web-routes"));
});

test("rejects an exportless internal DOM widget without a launch anchor", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      dependencies: { react: "latest", "react-dom": "latest" },
    },
    "src/index.tsx": "document.querySelector('#mount'); export const Widget = () => <button>Widget</button>;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("source:browser-dom"));
  assert.ok(result.reasons.some((reason) => /runnable website/i.test(reason)));
});

test("rejects a React Native Expo Router application without a web runtime", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      main: "expo-router/entry",
      dependencies: {
        expo: "latest",
        react: "latest",
        "react-native": "latest",
        "expo-router": "latest",
      },
    },
    "app/index.tsx": "import { View } from 'react-native'; export default function Home() { return <View />; }",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("runtime:native-mobile"));
  assert.ok(!result.signals.includes("source:web-routes"));
});

test("rejects a browser-extension-only Vite project", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest" },
      devDependencies: { vite: "latest" },
    },
    "manifest.json": {
      manifest_version: 3,
      name: "Extension",
      version: "1.0.0",
      action: { default_popup: "index.html" },
    },
    "vite.config.ts": "export default {};",
    "index.html": "<!doctype html><html><body><main id=\"root\"></main></body></html>",
    "src/index.tsx": "document.getElementById('root');",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("runtime:browser-extension"));
});

for (const [name, dependencies, extraFiles] of [
  ["Electron", { electron: "latest", react: "latest", "react-dom": "latest", vite: "latest" }, {}],
  ["Tauri", { "@tauri-apps/api": "latest", "@tauri-apps/cli": "latest", react: "latest", "react-dom": "latest", vite: "latest" }, {
    "src-tauri/tauri.conf.json": { productName: "Desktop" },
  }],
]) {
  test(`rejects a ${name}-only Vite desktop application`, async (t) => {
    const project = await makeFixture(t, {
      "package.json": { private: true, scripts: { dev: "vite" }, dependencies },
      "vite.config.ts": "export default {};",
      "index.html": "<!doctype html><html><body><main id=\"root\"></main></body></html>",
      "src/index.tsx": "document.getElementById('root');",
      ...extraFiles,
    });

    const result = await detectWebProject(project);

    assert.equal(result.isWebsite, false);
    assert.ok(result.signals.includes("runtime:desktop-app"));
  });
}

test("accepts a separate website workspace beside a desktop application", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      workspaces: ["apps/*"],
      dependencies: { electron: "latest" },
    },
    "apps/web/package.json": {
      private: true,
      scripts: { dev: "vite" },
      dependencies: { react: "latest", "react-dom": "latest", vite: "latest" },
    },
    "apps/web/vite.config.ts": "export default {};",
    "apps/web/index.html": "<!doctype html><html><body><main id=\"root\"></main></body></html>",
    "apps/web/src/index.tsx": "document.getElementById('root');",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.ok(result.signals.includes("runtime:desktop-app"));
  assert.ok(result.signals.includes("entry:valid-index-html"));
});

test("rejects a private monorepo containing only a browser component library", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, workspaces: ["packages/*"] },
    "packages/ui/package.json": {
      private: true,
      exports: "./src/index.tsx",
      dependencies: { react: "latest", "react-dom": "latest" },
    },
    "packages/ui/src/index.tsx": "document.querySelector('#mount'); export const Widget = () => <button>Widget</button>;",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, false);
  assert.ok(result.signals.includes("package:library"));
  assert.ok(!result.signals.includes("source:web-routes"));
});

test("prefers a runnable framework over an unrelated earlier peer dependency", async (t) => {
  const project = await makeFixture(t, {
    "package.json": {
      private: true,
      scripts: { dev: "astro dev" },
      dependencies: { astro: "latest" },
      peerDependencies: { next: "latest" },
    },
    "astro.config.mjs": "export default {};",
    "src/pages/index.astro": "<main>Home</main>",
  });

  const result = await detectWebProject(project);
  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "Astro");
  assert.ok(result.signals.includes("framework-peer:next.js"));
});

const frameworkLibraries = [
  ["Astro", "astro", "astro.config.mjs", "src/Widget.astro", "<div><slot /></div>"],
  ["Vue", "vue", null, "src/Widget.vue", "<template><button><slot /></button></template>"],
  ["Svelte", "svelte", null, "src/Widget.svelte", "<button><slot /></button>"],
  ["Angular", "@angular/core", "angular.json", "src/widget.ts", "export class Widget {}"],
];

for (const [name, dependency, config, sourcePath, source] of frameworkLibraries) {
  test(`rejects a publishable ${name} component library`, async (t) => {
    const entries = {
      "package.json": {
        private: false,
        main: "./dist/index.js",
        exports: { ".": "./dist/index.js" },
        peerDependencies: { [dependency]: "latest" },
      },
      [sourcePath]: source,
    };
    if (config === "angular.json") {
      entries[config] = JSON.stringify({ projects: { widgets: { projectType: "library" } } });
    } else if (config) {
      entries[config] = "export default {};";
    }
    const project = await makeFixture(t, entries);

    const result = await detectWebProject(project);

    assert.equal(result.isWebsite, false);
    assert.equal(result.framework, name);
    assert.ok(result.signals.includes("package:library"));
  });
}

test("uses weighted route and client signals for a full-stack website", async (t) => {
  const project = await makeFixture(t, {
    "package.json": { private: true, dependencies: { react: "latest", "react-dom": "latest" } },
    "app/page.tsx": "export default function Page() { return <main>Home</main>; }",
    "app/settings/page.tsx": "export default function Settings() { return <main>Settings</main>; }",
  });

  const result = await detectWebProject(project);

  assert.equal(result.isWebsite, true);
  assert.equal(result.framework, "React");
  assert.ok(result.signals.includes("source:web-routes"));
});

test("website detection does not read supplied paths through linked repository ancestors", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-linked-root-"));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-linked-outside-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  await fs.writeFile(
    path.join(outside, "index.html"),
    "<!doctype html><html><body><main>Outside</main></body></html>",
  );
  const linked = path.join(root, "linked");
  try {
    await fs.symlink(outside, linked, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "UNKNOWN"].includes(error?.code)) {
      t.skip(`directory links are unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  const result = await detectWebProject({
    root,
    files: [{
      absolute: path.join(linked, "index.html"),
      relative: "linked/index.html",
      name: "index.html",
      extension: ".html",
    }],
  });

  assert.equal(result.isWebsite, false);
  assert.ok(!result.signals.includes("entry:valid-index-html"));
});

test("website detection rejects an outside descriptor disguised with an internal route path", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-forged-root-"));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-forged-outside-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  t.after(() => fs.rm(outside, { recursive: true, force: true }));
  const outsideSource = path.join(outside, "page.tsx");
  await fs.writeFile(outsideSource, "export default () => <main>Outside</main>;");

  const result = await detectWebProject({
    root,
    files: [{
      absolute: outsideSource,
      relative: "app/page.tsx",
      name: "page.tsx",
      extension: ".tsx",
    }],
  });

  assert.equal(result.isWebsite, false);
  assert.ok(!result.signals.includes("source:web-routes"));
});

test("collector exposes verified metadata for web assets without reading binary contents", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "modular-project-assets-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const assetPath = path.join(root, "public", "hero.webp");
  await fs.mkdir(path.dirname(assetPath), { recursive: true });
  await fs.writeFile(assetPath, Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]));
  await fs.writeFile(path.join(root, "archive.zip"), Buffer.from([1, 2, 3, 4]));

  const inventory = await collectFiles(root, { maxFileBytes: 4 });
  const asset = inventory.files.find((file) => file.relative === "public/hero.webp");

  assert.ok(asset);
  assert.equal(isWebAssetFile(asset), true);
  assert.equal(asset.contentReadable, false);
  assert.equal(asset.assetMetadata, true);
  assert.equal(asset.size, 8);
  assert.equal(inventory.skipped.assetMetadata, 1);
  assert.equal(inventory.files.some((file) => file.relative === "archive.zip"), false);
  assert.deepEqual(await verifyFileMetadata(asset, { root }), {
    absolute: assetPath,
    relative: "public/hero.webp",
    extension: ".webp",
    size: 8,
  });

  await fs.writeFile(assetPath, Buffer.from([7, 6, 5, 4, 3, 2, 1, 0]));
  assert.equal(await verifyFileMetadata(asset, { root }), null);
});
