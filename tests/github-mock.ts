/**
 * An in-memory GitHub (REST subset) plus the invite-inbox Worker, as a fetch function.
 * Emulates the behaviour the provider relies on:
 *  - private repos: only owner and accepted collaborators read and write; public: anyone reads
 *  - Contents API compare-and-swap: create of an existing path -> 422, wrong sha -> 409
 *  - files over 1 MB come back without content (use the git blob endpoint)
 *  - only the owner manages collaborators and invitations; invitations are accepted by the invitee
 *  - a GitHub App installed on "select repositories" with every repo the owner creates auto-added
 *  - the Worker inbox: keyed by invitee, checks the invitation is on the caller's repo
 * Plus test hooks: rewrite a file behind everyone's back (force-push), rate-limit, request log.
 */
import { createHash } from 'node:crypto';

interface File {
  sha: string;
  content: Buffer;
}
interface Repo {
  owner: string;
  name: string;
  private: boolean;
  collaborators: Set<string>;
  invitations: Map<number, string>;
  files: Map<string, File>;
  topics: string[];
  description: string;
}

type Init = { method?: string; headers?: Record<string, string>; body?: string };

const sha = (b: Buffer) => createHash('sha1').update(b).digest('hex');

export class MockGitHub {
  readonly users = new Map<string, { id: number; token: string }>();
  readonly repos = new Map<string, Repo>();
  readonly inbox = new Map<number, { id: number; from: string; from_id: number; created_at: string; expires_at: string }[]>();
  readonly log: string[] = [];
  /** Remaining requests before a 403 rate-limit response (per token). */
  readonly budget = new Map<string, number>();
  private nextId = 1000;
  readonly api = 'https://api.github.test';
  readonly worker = 'https://worker.test';

  addUser(login: string) {
    const id = this.nextId++;
    const token = `tok-${login}`;
    this.users.set(login.toLowerCase(), { id, token });
    return { login: login.toLowerCase(), id, token };
  }

  private who(init?: Init): string | undefined {
    const auth = init?.headers?.Authorization ?? init?.headers?.authorization;
    const tok = auth?.replace(/^Bearer /, '');
    for (const [login, u] of this.users) if (u.token === tok) return login;
    return undefined;
  }

  canRead(r: Repo, u?: string) {
    return !r.private || (u !== undefined && (u === r.owner || r.collaborators.has(u)));
  }
  canWrite(r: Repo, u?: string) {
    return u !== undefined && (u === r.owner || r.collaborators.has(u));
  }

  /** Test hook: the repo owner (or GitHub) rewrites a file, as a force-push would. */
  rewrite(fullName: string, path: string, content: Uint8Array) {
    const r = this.repos.get(fullName)!;
    const b = Buffer.from(content);
    r.files.set(path, { sha: sha(b), content: b });
  }

  fetch = async (url: string, init: Init = {}) => {
    const method = (init.method ?? 'GET').toUpperCase();
    const u = new URL(url);
    const user = this.who(init);
    this.log.push(`${method} ${u.pathname}`);
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (user) {
      const left = this.budget.get(user);
      if (left !== undefined) {
        if (left <= 0) return resp(403, { message: 'API rate limit exceeded' }, { 'x-ratelimit-remaining': '0' });
        this.budget.set(user, left - 1);
      }
    }
    if (url.startsWith(this.worker)) return this.workerRoute(method, u, user, body);
    return this.route(method, decodeURIComponent(u.pathname), u.searchParams, user, body);
  };

  private route(method: string, path: string, q: URLSearchParams, user: string | undefined, body: any) {
    let m: RegExpMatchArray | null;
    if (method === 'POST' && path === '/user/repos') {
      if (!user) return resp(401, {});
      const full = `${user}/${body.name}`.toLowerCase();
      if (this.repos.has(full)) return resp(422, { message: 'name already exists on this account' });
      this.repos.set(full, { owner: user, name: body.name.toLowerCase(), private: !!body.private, collaborators: new Set(), invitations: new Map(), files: new Map(), topics: [], description: body.description ?? '' });
      if (body.auto_init) this.repos.get(full)!.files.set('README.md', { sha: sha(Buffer.from('')), content: Buffer.from('') });
      return resp(201, { full_name: full, name: body.name, private: !!body.private });
    }
    if ((m = path.match(/^\/repos\/([^/]+)\/([^/]+)$/)) && method === 'GET') {
      const r = this.repos.get(`${m[1]}/${m[2]}`.toLowerCase());
      if (!r || !this.canRead(r, user)) return resp(404, { message: 'Not Found' });
      return resp(200, { full_name: `${r.owner}/${r.name}`, private: r.private });
    }
    if ((m = path.match(/^\/repos\/([^/]+)\/([^/]+)\/(.*)$/))) {
      const r = this.repos.get(`${m[1]}/${m[2]}`.toLowerCase());
      if (!r || !this.canRead(r, user)) return resp(404, { message: 'Not Found' });
      return this.repoRoute(r, method, m[3]!, user, body);
    }
    if (method === 'GET' && path === '/user/installations') {
      if (!user) return resp(401, {});
      const owners = new Set<string>();
      for (const r of this.repos.values()) if (this.canWrite(r, user)) owners.add(r.owner);
      return resp(200, { installations: [...owners].map((o) => ({ id: this.users.get(o)!.id, account: { login: o } })) });
    }
    if ((m = path.match(/^\/user\/installations\/(\d+)\/repositories$/)) && method === 'GET') {
      const owner = [...this.users].find(([, v]) => v.id === Number(m![1]))?.[0];
      const page = Number(q.get('page') ?? 1);
      const all = [...this.repos.values()].filter((r) => r.owner === owner && this.canWrite(r, user));
      const slice = all.slice((page - 1) * 100, page * 100);
      return resp(200, { total_count: all.length, repositories: slice.map((r) => ({ name: r.name, full_name: `${r.owner}/${r.name}` })) });
    }
    if ((m = path.match(/^\/user\/repository_invitations\/(\d+)$/)) && method === 'PATCH') {
      const id = Number(m[1]);
      for (const r of this.repos.values()) {
        const who = r.invitations.get(id);
        if (who === undefined) continue;
        if (who !== user) return resp(404, {});
        r.invitations.delete(id);
        r.collaborators.add(user);
        return resp(204, undefined);
      }
      return resp(404, { message: 'Not Found' });
    }
    return resp(404, { message: `mock: no route ${method} ${path}` });
  }

  private repoRoute(r: Repo, method: string, rest: string, user: string | undefined, body: any) {
    let m: RegExpMatchArray | null;
    const isOwner = user === r.owner;
    if ((m = rest.match(/^contents\/(.*)$/))) {
      const path = m[1]!;
      if (method === 'GET') {
        const f = r.files.get(path);
        if (f) {
          const big = f.content.length > 1024 * 1024;
          return resp(200, { type: 'file', name: path.split('/').pop(), path, sha: f.sha, size: f.content.length, encoding: big ? 'none' : 'base64', content: big ? '' : f.content.toString('base64').replace(/(.{60})/g, '$1\n') });
        }
        const prefix = path + '/';
        const names = new Map<string, { type: string; sha: string }>();
        for (const [p, file] of r.files) {
          if (!p.startsWith(prefix)) continue;
          const restp = p.slice(prefix.length);
          const [first, ...more] = restp.split('/');
          names.set(first!, more.length ? { type: 'dir', sha: 'dir' } : { type: 'file', sha: file.sha });
        }
        if (names.size === 0) return resp(404, { message: 'Not Found' });
        return resp(200, [...names].map(([name, v]) => ({ name, path: prefix + name, sha: v.sha, type: v.type })));
      }
      if (!this.canWrite(r, user)) return resp(r.private ? 404 : 403, { message: 'no write access' });
      if (method === 'PUT') {
        const cur = r.files.get(path);
        if (cur && !body.sha) return resp(422, { message: 'Invalid request.\n\n"sha" wasn\'t supplied.' });
        if (cur && body.sha !== cur.sha) return resp(409, { message: `${path} does not match ${body.sha}` });
        if (!cur && body.sha) return resp(422, { message: 'sha given for a new file' });
        const content = Buffer.from(body.content, 'base64');
        r.files.set(path, { sha: sha(content), content });
        return resp(cur ? 200 : 201, { content: { sha: sha(content) } });
      }
      if (method === 'DELETE') {
        const cur = r.files.get(path);
        if (!cur) return resp(404, {});
        if (body.sha !== cur.sha) return resp(409, { message: 'sha mismatch' });
        r.files.delete(path);
        return resp(200, {});
      }
    }
    if ((m = rest.match(/^git\/blobs\/([0-9a-f]+)$/)) && method === 'GET') {
      for (const f of r.files.values()) if (f.sha === m[1]) return resp(200, { sha: f.sha, encoding: 'base64', content: f.content.toString('base64') });
      return resp(404, {});
    }
    if (rest === 'topics' && method === 'PUT') {
      if (!isOwner) return resp(403, {});
      r.topics = body.names;
      return resp(200, { names: r.topics });
    }
    if (rest.startsWith('collaborators') && method === 'GET' && rest.split('?')[0] === 'collaborators') {
      if (!this.canWrite(r, user)) return resp(403, {});
      return resp(200, [r.owner, ...r.collaborators].map((login) => ({ login })));
    }
    if ((m = rest.match(/^collaborators\/([^/]+)$/))) {
      const who = m[1]!.toLowerCase();
      if (!isOwner) return resp(403, { message: 'Must have admin rights to Repository.' });
      if (method === 'PUT') {
        if (!this.users.has(who)) return resp(404, {});
        if (r.collaborators.has(who) || who === r.owner) return resp(204, undefined);
        for (const [id, w] of r.invitations) if (w === who) return resp(201, { id, invitee: { login: who } });
        const id = this.nextId++;
        r.invitations.set(id, who);
        return resp(201, { id, invitee: { login: who } });
      }
      if (method === 'DELETE') {
        r.collaborators.delete(who);
        return resp(204, undefined);
      }
    }
    if (rest === 'invitations' && method === 'GET') {
      if (!isOwner) return resp(403, {});
      return resp(200, [...r.invitations].map(([id, login]) => ({ id, invitee: { login } })));
    }
    if ((m = rest.match(/^invitations\/(\d+)$/)) && method === 'DELETE') {
      if (!isOwner) return resp(403, {});
      r.invitations.delete(Number(m[1]));
      return resp(204, undefined);
    }
    return resp(404, { message: `mock: no repo route ${method} ${rest}` });
  }

  private workerRoute(method: string, u: URL, user: string | undefined, body: any) {
    if (!user) return resp(401, { error: 'unauthorized' });
    const me = this.users.get(user)!;
    if (method === 'POST' && u.pathname === '/invites') {
      const r = this.repos.get(`${user}/${String(body.repo).toLowerCase()}`);
      const invitee = r?.invitations.get(Number(body.invite_id));
      if (!r || !invitee) return resp(404, { error: 'no such invitation on your repo' });
      const inv = this.users.get(invitee)!;
      const list = this.inbox.get(inv.id) ?? [];
      const now = Date.now();
      list.push({ id: Number(body.invite_id), from: user, from_id: me.id, created_at: new Date(now).toISOString(), expires_at: new Date(now + 7 * 86_400_000).toISOString() });
      this.inbox.set(inv.id, list);
      return resp(201, { ok: true, invitee_id: inv.id });
    }
    if (method === 'GET' && u.pathname === '/invites') return resp(200, { invites: this.inbox.get(me.id) ?? [] });
    const m = u.pathname.match(/^\/invites\/(\d+)$/);
    if (method === 'DELETE' && m) {
      this.inbox.set(me.id, (this.inbox.get(me.id) ?? []).filter((i) => i.id !== Number(m[1])));
      return resp(200, { ok: true });
    }
    return resp(404, { error: 'not found' });
  }
}

function resp(status: number, data: unknown, headers: Record<string, string> = {}) {
  const text = data === undefined ? '' : JSON.stringify(data);
  return {
    status,
    headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
    json: async () => (text ? JSON.parse(text) : undefined),
    text: async () => text,
  };
}
