import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, copyFile, writeFile, readFile, readdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {serve} from '../demo/serve.mjs';

test('static build excludes stale artifacts and hashes every deployed asset', async () => {
  const root = await mkdtemp(join(tmpdir(), 'helper-build-test-'));
  try {
    const demo = join(root, 'demo'), out = join(demo, 'dist');
    await mkdir(out, {recursive:true});
    await copyFile(new URL('../demo/build.mjs', import.meta.url), join(demo, 'build.mjs'));
    const assets = ['index.html', 'style.css', 'app.js', 'client.js', 'zip.js'];
    for (const name of assets) await writeFile(join(demo, name), 'fixture:' + name);
    await writeFile(join(out, 'old-attestation.jsonl'), 'stale');
    const env = {...process.env};
    delete env.GITHUB_ACTIONS; delete env.GITHUB_SHA; delete env.GITHUB_STEP_SUMMARY;
    execFileSync(process.execPath, [join(demo, 'build.mjs')], {env});
    assert.deepEqual((await readdir(out)).sort(), [...assets, 'build.json', 'SHA256SUMS'].sort());
    const build = JSON.parse(await readFile(join(out, 'build.json')));
    assert.equal(build.commit, null); assert.equal(build.dirty, null);
    for (const name of assets) {
      assert.equal(build.files[name], createHash('sha256').update(await readFile(join(out, name))).digest('hex'));
    }
  } finally { await rm(root, {recursive:true, force:true}); }
});

test('local server reports an occupied port rather than leaving startup pending', async () => {
  const server = await serve('demo', 0);
  try { await assert.rejects(serve('demo', server.address().port), {code:'EADDRINUSE'}); }
  finally { await new Promise(resolve => server.close(resolve)); }
});
