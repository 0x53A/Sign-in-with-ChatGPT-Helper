import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, extname, sep} from 'node:path';
export async function serve(root = 'web', port = 8767) {
  const base = resolve(root);
  const server = http.createServer(async (req, res) => {
    try {
      let path = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      if (path.endsWith('/')) path += 'index.html';
      const file = resolve(base, '.' + path);
      if (!file.startsWith(base + sep)) throw Error('Outside root');
      const bytes = await readFile(file);
      res.writeHead(200, {'Content-Type': {'.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.json':'application/json'}[extname(file)] || 'application/octet-stream', 'Cache-Control':'no-store'}); res.end(bytes);
    } catch { res.writeHead(404); res.end('Not found'); }
  });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve)); return server;
}
if (process.argv[1]?.endsWith('/serve.mjs')) { const server = await serve(process.argv[2] || 'web', Number(process.env.PORT || 8767)); console.log(`http://127.0.0.1:${server.address().port}`); }
