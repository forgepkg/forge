// Third-party notices for the npm packages the web UI is built from: the
// production dependencies of web/package.json, as `pnpm licenses list --prod
// --json` reports them (the file given as the only argument). Prints each
// package with its declared license and the license files it ships, for
// /usr/share/doc/forge/THIRD-PARTY-WEB.txt in the image (see the Dockerfile).
//
//   node docker/licenses/web-notices.mjs licenses.json > THIRD-PARTY-WEB.txt
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [reportPath] = process.argv.slice(2);
if (!reportPath) {
  console.error("usage: web-notices.mjs <pnpm licenses list --prod --json output>");
  process.exit(2);
}
const report = JSON.parse(readFileSync(reportPath, "utf8"));
// pnpm reports some failures (a missing store index, …) as an `error` object
// on stdout and still exits 0.
if (report.error) {
  console.error(`pnpm licenses: ${report.error.code}: ${report.error.message}`);
  process.exit(1);
}

const LICENSE_FILE = /^(licen[cs]e|copying|notice)([.-].*)?$/i;
const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// One entry per installed package version; pnpm groups them by license.
const packages = [];
for (const [license, entries] of Object.entries(report)) {
  for (const entry of entries) {
    for (const dir of entry.paths) {
      const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      const files = readdirSync(dir)
        .filter((name) => LICENSE_FILE.test(name))
        .sort(byText);
      packages.push({
        name: manifest.name,
        version: manifest.version,
        license,
        homepage: entry.homepage,
        texts: files.map((name) => ({
          name,
          text: readFileSync(join(dir, name), "utf8").replace(/\r\n?/g, "\n").trimEnd(),
        })),
      });
    }
  }
}
if (packages.length === 0) {
  console.error("pnpm licenses reported no packages");
  process.exit(1);
}
packages.sort((a, b) => byText(a.name, b.name) || byText(a.version, b.version));

const counts = new Map();
for (const { license } of packages) counts.set(license, (counts.get(license) ?? 0) + 1);

const out = [
  "THIRD-PARTY NOTICES: NPM PACKAGES IN THE WEB UI",
  "",
  "The web UI (/app/web/dist) is built from the third-party npm packages listed",
  "below, the production dependencies of web/package.json, each under the",
  "license given with it. The license of envisia-forge itself is in LICENSE,",
  "next to this file.",
  "",
  "Generated from `pnpm licenses list --prod` and the packages' license files",
  "(docker/licenses/web-notices.mjs).",
  "",
  "Licenses, with the number of packages under each:",
  ...[...counts]
    .sort(([a, x], [b, y]) => y - x || byText(a, b))
    .map(([license, count]) => `  ${license}: ${count}`),
];
for (const pkg of packages) {
  out.push("", "=".repeat(80), `${pkg.name} ${pkg.version} (${pkg.license})`);
  if (pkg.homepage) out.push(pkg.homepage);
  if (pkg.texts.length === 0) {
    console.error(`warning: ${pkg.name}@${pkg.version} ships no license file`);
    out.push("", `The package ships no license file; it declares ${pkg.license}.`);
  }
  for (const { name, text } of pkg.texts) {
    if (pkg.texts.length > 1) out.push("", `--- ${name}`);
    out.push("", text);
  }
}
process.stdout.write(`${out.join("\n")}\n`);
