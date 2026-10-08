// Regenerates src/data/ecs-fields.json from Elastic's published ECS field list.
//   node scripts/gen-ecs-fields.mjs [git-ref]        (default ref: v9.5.0)
// Only field NAMES and which of them are free-form objects are kept, so the bundle stays small.
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ref = process.argv[2] || "v9.5.0";
const url = `https://raw.githubusercontent.com/elastic/ecs/${ref}/generated/csv/fields.csv`;
const res = await fetch(url);
if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
const text = await res.text();

// Minimal RFC 4180 parser: the Example/Description columns contain quoted commas and newlines.
function parseCsv(src) {
  const rows = []; let row = [], cur = "", q = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) { if (c === '"') { if (src[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(cur); cur = ""; }
    else if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
    else if (c !== "\r") cur += c;
  }
  if (cur || row.length) { row.push(cur); rows.push(row); }
  return rows;
}
const [head, ...rows] = parseCsv(text);
const col = (n) => head.indexOf(n);
const fields = [], objects = [];
let version = "";
for (const r of rows) {
  if (!r[col("Field")]) continue;
  version = r[col("ECS_Version")];
  fields.push(r[col("Field")]);
  if (["object", "flattened", "nested"].includes(r[col("Type")])) objects.push(r[col("Field")]);
}
fields.sort(); objects.sort();
const out = resolve(dirname(fileURLToPath(import.meta.url)), "../src/data/ecs-fields.json");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ source: url, version, fields, objects }) + "\n");
console.log(`wrote ${fields.length} fields (${objects.length} free-form objects), ECS ${version} -> ${out}`);
