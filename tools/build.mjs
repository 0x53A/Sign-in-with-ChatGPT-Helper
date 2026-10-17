import {readFile, writeFile, mkdir, copyFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const out = 'target/pages', files = ['index.html', 'style.css', 'app.js', 'client.js', 'zip.js'];
await mkdir(out, {recursive:true});
const hashes = {};
for (const name of files) { await copyFile(`web/${name}`, `${out}/${name}`); hashes[name] = createHash('sha256').update(await readFile(`${out}/${name}`)).digest('hex'); }
let commit = process.env.GITHUB_SHA || 'local-uncommitted';
if (!process.env.GITHUB_SHA) try { commit = execFileSync('git', ['rev-parse', 'HEAD'], {stdio:['ignore','pipe','ignore']}).toString().trim(); } catch {}
const build = {repository:'0x53A/Sign-in-with-ChatGPT-Helper', commit, run_id:process.env.GITHUB_RUN_ID || null, workflow:'.github/workflows/publish.yml', files:hashes};
await writeFile(`${out}/build.json`, JSON.stringify(build, null, 2) + '\n');
hashes['build.json'] = createHash('sha256').update(await readFile(`${out}/build.json`)).digest('hex');
await writeFile(`${out}/SHA256SUMS`, Object.entries(hashes).map(([name, hash]) => `${hash}  ${name}\n`).join(''));
if (process.env.GITHUB_STEP_SUMMARY) await writeFile(process.env.GITHUB_STEP_SUMMARY, `### Published application hashes\n\nSource: ${commit}\n\n\`\`\`\n${await readFile(`${out}/SHA256SUMS`, 'utf8')}\`\`\`\n`, {flag:'a'});
console.log(`Built ${out}; no service worker, updater or runtime dependencies.`);
