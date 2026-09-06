# Try Modular without a private repository

From the Modular checkout:

```console
npm run demo
```

The synthetic [basic-site](./basic-site/index.html) intentionally has an unnamed email input and missing page metadata. Its [legacy widget](./basic-site/legacy-widget.js) contains an unsafe HTML sink as static source; the page does not execute it. Do not deploy this fixture.

The command creates Markdown, JSON and SARIF reports under `examples/basic-site/Modular/`. It needs only Node.js and npm, performs a static scan and does not start a browser or contact a package registry. Generated reports are ignored by Git and excluded from the npm package. Findings are advisory by default, so a completed demo exits `0` even when it finds problems.

To see a severity gate fail with exit code `3`:

```console
node bin/modular.js check all --root examples/basic-site --fail-on high --no-color
```

For a real project, copy the settings from [modular.config.json](./modular.config.json) into that project's `.modular.json`. Set `$schema` to the installed package's schema path, or omit it; it is an editor hint. `failOnIncomplete` rejects incomplete requested coverage. Browser and advisory access still require explicit CLI flags.
