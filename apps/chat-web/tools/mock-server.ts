/**
 * Local test backend: the in-memory GitHub + Worker mock from keyhold's tests, served over
 * HTTP with CORS, plus the few endpoints the web app adds (/user, /users/:login, commits ETag,
 * repo delete, own installation). Also serves the mock build (dist-mock) at /.
 *   node tools/mock-server.mjs [port]
 */
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { MockGitHub } from '../../../tests/github-mock';

const port = Number(process.argv[2] ?? 8787);
const root = join(process.cwd(), 'dist-mock');
const gh = new MockGitHub();

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, If-None-Match, X-GitHub-Api-Version, Accept',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Expose-Headers': 'ETag, X-RateLimit-Remaining',
};

function userOf(auth: string | undefined) {
  const tok = auth?.replace(/^Bearer /, '');
  if (!tok?.startsWith('tok-')) return undefined;
  const login = tok.slice(4);
  if (!gh.users.has(login)) gh.addUser(login);
  return login;
}

const TYPES: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.svg': 'image/svg+xml' };

createServer(async (req, res) => {
  const url = new URL(req.url!, `http://localhost:${port}`);
  const send = (status: number, body: string | Buffer = '', headers: Record<string, string> = {}) => {
    res.writeHead(status, { ...cors, 'X-RateLimit-Remaining': '4999', ...headers });
    res.end(body);
  };
  if (req.method === 'OPTIONS') return send(204);
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const body = Buffer.concat(chunks).toString() || undefined;
  const auth = req.headers.authorization;
  const user = userOf(auth);
  const json = (status: number, data: unknown, h: Record<string, string> = {}) => send(status, JSON.stringify(data), { 'Content-Type': 'application/json', ...h });

  if (url.pathname.startsWith('/gh/') || url.pathname.startsWith('/worker/')) {
    const isGh = url.pathname.startsWith('/gh/');
    const rest = url.pathname.slice(isGh ? 3 : 7) + url.search;
    const path = decodeURIComponent(url.pathname.slice(isGh ? 3 : 7));
    if (isGh) {
      if (path === '/user') return user ? json(200, { login: user, id: gh.users.get(user)!.id }) : json(401, {});
      let m = path.match(/^\/users\/([^/]+)$/);
      if (m) return gh.users.has(m[1]!.toLowerCase()) ? json(200, { login: m[1], type: 'User' }) : json(404, { message: 'Not Found' });
      m = path.match(/^\/repos\/([^/]+)\/([^/]+)\/commits$/);
      if (m && req.method === 'GET') {
        const r = gh.repos.get(`${m[1]}/${m[2]}`.toLowerCase());
        if (!r || !gh.canRead(r, user)) return json(404, { message: 'Not Found' });
        const h = createHash('sha1');
        for (const [p, f] of [...r.files].sort()) h.update(`${p}:${f.sha};`);
        const etag = `"${h.digest('hex')}"`;
        if (req.headers['if-none-match'] === etag) return send(304, '', { ETag: etag });
        return json(200, [{ sha: etag }], { ETag: etag });
      }
      m = path.match(/^\/repos\/([^/]+)\/([^/]+)$/);
      if (m && req.method === 'DELETE') {
        const k = `${m[1]}/${m[2]}`.toLowerCase();
        const r = gh.repos.get(k);
        if (!r) return send(404);
        if (r.owner !== user) return json(403, {});
        gh.repos.delete(k);
        return send(204);
      }
      if (path === '/user/installations' && user) {
        const r = await gh.fetch(gh.api + rest, { method: 'GET', headers: { Authorization: auth! } });
        const data = (await r.json()) as { installations: { id: number; account: { login: string } }[] };
        if (!data.installations.some((i) => i.account.login === user)) data.installations.push({ id: gh.users.get(user)!.id, account: { login: user } });
        return json(200, data);
      }
    }
    const r = await gh.fetch((isGh ? gh.api : gh.worker) + rest, { method: req.method, headers: auth ? { Authorization: auth } : {}, body });
    const text = await r.text();
    return send(r.status, text, text ? { 'Content-Type': 'application/json' } : {});
  }

  // static files
  let p = normalize(url.pathname).replace(/^(\.\.[/\\])+/, '');
  if (p === '/' || p === '') p = '/index.html';
  try {
    const data = await readFile(join(root, p));
    return send(200, data, {
      'Content-Type': TYPES[extname(p)] ?? 'application/octet-stream',
      // Same policy as production (public/_headers), with the mock API as 'self'.
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https://github.com https://avatars.githubusercontent.com; connect-src 'self' https://api.github.com; frame-ancestors 'none'; base-uri 'none'",
    });
  } catch {
    return send(404, 'not found');
  }
}).listen(port, () => console.log(`mock backend on http://localhost:${port}`));
