/**
 * GitHub storage provider: implements the remote storage kinds with GitHub repos.
 *
 *   {login}/keyhold-id    public  box 3  directory: dir/{index}          (create-only files)
 *   {login}/keyhold-home  private box 9  vault/{name}, box 12 items/{id} (sealed with K)
 *   {owner}/ghchat-xxxx   private per chat (the "space"):
 *                                 box 5  log/{index}       create-only = compare-and-swap
 *                                 box 6  mail/{day}/{id}
 *                                 box 7  blob/{id}
 *                                 box 8  drop/{tag}/{id}   deleted after read (stays in git history)
 *   Worker                        box 11 invite inbox (invitation ids only)
 *   box 4 (claim-once) is not provided: GitHub can't hand an item to exactly one taker.
 *
 * Compare-and-swap comes from the Contents API: creating a path that exists fails (422), and
 * updating needs the current blob sha (409 on mismatch). Channel side effects use the repo
 * collaborator API; on personal repos only the owner can invite or remove.
 *
 * Everything written is ciphertext or signed public data. Repo names, descriptions and topics
 * are plaintext, so they are neutral and identical for every chat.
 */
import { randomBytes, toHex } from '../../util/bytes.js';
import { KeyholdError } from '../../util/errors.js';
import type {
  Address,
  Bytes,
  CasResult,
  Capability,
  ChannelAccess,
  GrantResult,
  InviteInbox,
  MailboxItem,
  SpaceRef,
  StorageProvider,
  Versioned,
} from '../../storage/interfaces.js';
import { GitHubClient, type FetchFn } from './client.js';

export interface GitHubProviderOptions {
  fetch: FetchFn;
  /** GitHub App user access token. */
  token: string;
  /** The signed-in user's login. */
  login: string;
  /** Base URL of the invite-inbox Worker. */
  workerUrl: string;
  apiBase?: string;
  directoryRepo?: string;
  homeRepo?: string;
  chatPrefix?: string;
  /** Shown on every chat repo. Must not contain anything personal. */
  description?: string;
  now?: () => number;
}

export const GITHUB_PREFIX = 'github:';
export const toAddress = (login: string): Address => GITHUB_PREFIX + login.toLowerCase();
export function loginOf(address: Address): string {
  if (!address.startsWith(GITHUB_PREFIX)) throw new KeyholdError('config', `not a GitHub address: ${address}`);
  return address.slice(GITHUB_PREFIX.length);
}

const pad = (n: number) => String(n).padStart(8, '0');
const logPath = (i: number) => `log/${String(Math.floor(i / 1000)).padStart(5, '0')}/${pad(i)}`;
const rid = () => toHex(randomBytes(10));

function toB64(b: Bytes): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/\s/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function splitSpace(space: SpaceRef): [string, string] {
  const [o, r] = space.split('/');
  if (!o || !r) throw new KeyholdError('config', `bad space ${space}`);
  return [o, r];
}

interface DirEntry {
  name: string;
  path: string;
  sha: string;
  type: string;
}

export function githubProvider(o: GitHubProviderOptions): StorageProvider & { client: GitHubClient } {
  const gh = new GitHubClient({ fetch: o.fetch, token: o.token, apiBase: o.apiBase });
  const login = o.login.toLowerCase();
  const self = toAddress(login);
  const dirRepo = o.directoryRepo ?? 'keyhold-id';
  const homeRepo = o.homeRepo ?? 'keyhold-home';
  const prefix = o.chatPrefix ?? 'ghchat-';
  const description = o.description ?? 'Encrypted chat data. Only the chat app of its members can read it.';
  const now = o.now ?? Date.now;
  const enc = encodeURIComponent;
  const contents = (owner: string, repo: string, path: string) => `/repos/${enc(owner)}/${enc(repo)}/contents/${path.split('/').map(enc).join('/')}`;

  async function getFile(owner: string, repo: string, path: string): Promise<Versioned | undefined> {
    const r = await gh.call('GET', contents(owner, repo, path));
    if (r.status === 404) return undefined;
    if (r.status !== 200 || Array.isArray(r.data)) throw new KeyholdError(r.status === 403 ? 'forbidden' : 'config', `read ${path}: ${r.status}`);
    let data: Uint8Array<ArrayBuffer>;
    if (r.data.encoding === 'base64' && typeof r.data.content === 'string' && (r.data.content.length > 0 || r.data.size === 0)) data = fromB64(r.data.content);
    else {
      // Files over 1 MB come without content: fetch the git blob instead.
      const b = await gh.expect('GET', `/repos/${enc(owner)}/${enc(repo)}/git/blobs/${r.data.sha}`, [200]);
      data = fromB64(b.data.content);
    }
    return { data, version: r.data.sha };
  }

  async function listDir(owner: string, repo: string, path: string, mustExist = true): Promise<DirEntry[]> {
    const r = await gh.call('GET', contents(owner, repo, path));
    if (r.status === 404) {
      // GitHub answers 404 both for "no such folder" and "no access to a private repo".
      if (mustExist && (await gh.call('GET', `/repos/${enc(owner)}/${enc(repo)}`)).status === 404) {
        throw new KeyholdError('forbidden', `no access to ${owner}/${repo}`);
      }
      return [];
    }
    if (r.status === 403) throw new KeyholdError('forbidden', `list ${path}: no access`);
    if (r.status !== 200 || !Array.isArray(r.data)) throw new KeyholdError('config', `list ${path}: ${r.status}`);
    return (r.data as DirEntry[]).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  }

  async function putFile(owner: string, repo: string, path: string, data: Bytes, sha: string | null): Promise<CasResult> {
    const body: Record<string, unknown> = { message: 'update', content: toB64(data) };
    if (sha) body.sha = sha;
    const r = await gh.call('PUT', contents(owner, repo, path), body);
    if (r.status === 200 || r.status === 201) return 'ok';
    if (r.status === 409 || r.status === 422) return 'conflict';
    if (r.status === 404 && sha === null) return 'conflict';
    throw new KeyholdError(r.status === 403 || r.status === 404 ? 'forbidden' : 'config', `write ${path}: ${r.status}`);
  }

  async function deleteFile(owner: string, repo: string, path: string, sha: string): Promise<CasResult> {
    const r = await gh.call('DELETE', contents(owner, repo, path), { message: 'update', sha });
    if (r.status === 200 || r.status === 404) return r.status === 200 ? 'ok' : 'conflict';
    if (r.status === 409 || r.status === 422) return 'conflict';
    throw new KeyholdError('forbidden', `delete ${path}: ${r.status}`);
  }

  /** Create one of the user's own repos if it doesn't exist yet. */
  const ensured = new Set<string>();
  async function ensureOwnRepo(name: string, priv: boolean, desc: string) {
    if (ensured.has(name)) return;
    const r = await gh.call('GET', `/repos/${enc(login)}/${enc(name)}`);
    if (r.status === 404) {
      await gh.expect('POST', '/user/repos', [201, 422], { name, private: priv, auto_init: true, description: desc, has_issues: false, has_wiki: false, has_projects: false });
    } else if (r.status !== 200) throw new KeyholdError('forbidden', `cannot open ${name}`);
    ensured.add(name);
  }

  const readAll = async (owner: string, repo: string, entries: DirEntry[]) => {
    const out: Bytes[] = [];
    for (const e of entries) {
      const f = await getFile(owner, repo, e.path);
      if (f) out.push(f.data);
    }
    return out;
  };

  // ---- Mailbox with day buckets -----------------------------------------------------------
  const day = (t: number) => new Date(t).toISOString().slice(0, 10).replace(/-/g, '');
  const prevDay = (d: string) => day(Date.UTC(+d.slice(0, 4), +d.slice(4, 6) - 1, +d.slice(6, 8)) - 86_400_000);

  const channel: ChannelAccess = {
    self,
    async createSpace() {
      const name = prefix + rid();
      await gh.expect('POST', '/user/repos', [201], { name, private: true, auto_init: true, description, has_issues: false, has_wiki: false, has_projects: false });
      await gh.call('PUT', `/repos/${enc(login)}/${enc(name)}/topics`, { names: ['keyhold-chat'] });
      return `${login}/${name}`;
    },
    async listSpaces() {
      const out = new Set<string>();
      const inst = await gh.expect('GET', '/user/installations?per_page=100', [200]);
      for (const i of inst.data.installations ?? []) {
        for (let page = 1; page < 50; page++) {
          const r = await gh.expect('GET', `/user/installations/${i.id}/repositories?per_page=100&page=${page}`, [200]);
          for (const repo of r.data.repositories ?? []) if (String(repo.name).startsWith(prefix)) out.add(String(repo.full_name).toLowerCase());
          if ((r.data.repositories ?? []).length < 100) break;
        }
      }
      return [...out];
    },
    async canManage(space) {
      return splitSpace(space)[0] === login;
    },
    async members(space) {
      const [ow, re] = splitSpace(space);
      const c = await gh.expect('GET', `/repos/${enc(ow)}/${enc(re)}/collaborators?affiliation=direct&per_page=100`, [200]);
      const active = (c.data as { login: string }[]).map((u) => toAddress(u.login));
      if (!active.includes(toAddress(ow))) active.push(toAddress(ow));
      const pending: Address[] = [];
      if (ow === login) {
        const inv = await gh.expect('GET', `/repos/${enc(ow)}/${enc(re)}/invitations?per_page=100`, [200]);
        for (const i of inv.data as { invitee: { login: string } }[]) pending.push(toAddress(i.invitee.login));
      }
      return { active, pending };
    },
    async grant(space, address): Promise<GrantResult> {
      const [ow, re] = splitSpace(space);
      if (ow !== login) return { status: 'needs-manager' };
      const r = await gh.expect('PUT', `/repos/${enc(ow)}/${enc(re)}/collaborators/${enc(loginOf(address))}`, [201, 204], { permission: 'push' });
      if (r.status === 204) return { status: 'already-member' };
      return { status: 'invited', pointer: `${space}#${r.data.id}` };
    },
    async acceptGrant(pointer) {
      const id = pointer.split('#').pop()!;
      const r = await gh.call('PATCH', `/user/repository_invitations/${enc(id)}`);
      // 404/410: already accepted, withdrawn or expired. The inbox can lag (KV is eventually consistent).
      if (![204, 404, 410].includes(r.status)) throw new KeyholdError('forbidden', `accept invitation: ${r.status}`);
    },
    async revoke(space, address) {
      const [ow, re] = splitSpace(space);
      if (ow !== login) return 'needs-manager';
      const who = loginOf(address);
      if (who === login) return 'done';
      await gh.expect('DELETE', `/repos/${enc(ow)}/${enc(re)}/collaborators/${enc(who)}`, [204, 404]);
      const inv = await gh.expect('GET', `/repos/${enc(ow)}/${enc(re)}/invitations?per_page=100`, [200]);
      for (const i of inv.data as { id: number; invitee: { login: string } }[]) {
        if (i.invitee.login.toLowerCase() === who) await gh.expect('DELETE', `/repos/${enc(ow)}/${enc(re)}/invitations/${i.id}`, [204, 404]);
      }
      return 'done';
    },
  };

  const worker = o.workerUrl.replace(/\/$/, '');
  const workerCall = async (method: string, path: string, body?: unknown) => {
    gh.requests++;
    const res = await o.fetch(worker + path, {
      method,
      headers: { Authorization: `Bearer ${o.token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const t = await res.text();
    return { status: res.status, data: t ? JSON.parse(t) : undefined };
  };
  const inviteInbox: InviteInbox = {
    async send(_to, notice) {
      // The Worker checks the invitation exists on the caller's own repo and files it under the invitee.
      const [space, id] = notice.pointer.split('#');
      const [, repo] = splitSpace(space!);
      const r = await workerCall('POST', '/invites', { invite_id: Number(id), repo });
      if (r.status === 429) throw new KeyholdError('too_many_attempts', 'invite rate limit reached');
      if (r.status !== 201) throw new KeyholdError('config', `invite inbox: ${r.status}`);
    },
    async list() {
      const r = await workerCall('GET', '/invites');
      if (r.status !== 200) throw new KeyholdError('forbidden', `invite inbox: ${r.status}`);
      return (r.data.invites as { id: number; from: string; expires_at: string }[]).map((i) => ({
        id: String(i.id),
        from: toAddress(i.from),
        pointer: String(i.id),
        expiresAt: Date.parse(i.expires_at),
      }));
    },
    async delete(id) {
      await workerCall('DELETE', `/invites/${enc(id)}`);
    },
  };

  const caps = new Set<Capability>(['owner-managed-spaces']);

  return {
    name: 'github',
    client: gh,
    capabilities: caps,
    limits: { maxBlobBytes: 50 * 1024 * 1024, maxItemBytes: 1024 * 1024 },
    directory: {
      async read(owner) {
        const ow = loginOf(owner);
        return readAll(ow, dirRepo, await listDir(ow, dirRepo, 'dir', false));
      },
      async append(index, entry) {
        await ensureOwnRepo(dirRepo, false, 'Public keys for an end-to-end encrypted chat app.');
        const have = await listDir(login, dirRepo, 'dir', false);
        if (have.length !== index) return 'conflict';
        return putFile(login, dirRepo, `dir/${pad(index)}`, entry, null);
      },
    },
    inviteInbox,
    orderedLog: {
      // log/{shard}/{index}: a GitHub folder listing stops at 1,000 entries, so 1,000 per shard.
      async read(space, from) {
        const [ow, re] = splitSpace(space);
        const shards = (await listDir(ow, re, 'log')).filter((d) => d.type === 'dir' && Number(d.name) >= Math.floor(from / 1000));
        const out: Bytes[] = [];
        for (const sh of shards) {
          const entries = (await listDir(ow, re, sh.path)).filter((e) => Number(e.name) >= from);
          out.push(...(await readAll(ow, re, entries)));
        }
        return out;
      },
      async append(space, index, entry) {
        const [ow, re] = splitSpace(space);
        if (index > 0) {
          // Appends must be contiguous: refuse to leave a gap.
          const prev = await gh.call('GET', contents(ow, re, logPath(index - 1)));
          if (prev.status === 404) return 'conflict';
        }
        return putFile(ow, re, logPath(index), entry, null);
      },
    },
    mailbox: {
      async post(space, data) {
        const [ow, re] = splitSpace(space);
        const id = `${now().toString(36)}-${rid()}`;
        for (let attempt = 0; attempt < 5; attempt++) {
          if ((await putFile(ow, re, `mail/${day(now())}/${id}`, data, null)) === 'ok') return id;
        }
        throw new KeyholdError('conflict', 'could not post');
      },
      async list(space, cursor) {
        const [ow, re] = splitSpace(space);
        const c = cursor ? (JSON.parse(cursor) as { d: string; s: string[] }) : undefined;
        const seen = new Set(c?.s ?? []);
        // Posters bucket by their own clock: re-scan the previous day too, to tolerate skew.
        const min = c ? prevDay(c.d) : '';
        const days = (await listDir(ow, re, 'mail')).filter((d) => d.type === 'dir' && d.name >= min).map((d) => d.name);
        const items: MailboxItem[] = [];
        const keep: string[] = [];
        const last = days[days.length - 1] ?? c?.d ?? day(now());
        for (const d of days) {
          for (const f of await listDir(ow, re, `mail/${d}`)) {
            if (d >= prevDay(last)) keep.push(f.name);
            if (seen.has(f.name)) continue;
            const file = await getFile(ow, re, f.path);
            if (file) items.push({ id: f.name, data: file.data });
          }
        }
        return { items, cursor: JSON.stringify({ d: last, s: keep }) };
      },
    },
    blobs: {
      async put(space, data) {
        const [ow, re] = splitSpace(space);
        const id = rid();
        if ((await putFile(ow, re, `blob/${id}`, data, null)) !== 'ok') throw new KeyholdError('conflict', 'blob id clash');
        return id;
      },
      async get(space, ref) {
        const [ow, re] = splitSpace(space);
        return (await getFile(ow, re, `blob/${ref}`))?.data;
      },
      async delete(space, ref) {
        const [ow, re] = splitSpace(space);
        const f = await getFile(ow, re, `blob/${ref}`);
        if (f) await deleteFile(ow, re, `blob/${ref}`, f.version);
      },
    },
    dropBox: {
      async put(space, tag, data) {
        const [ow, re] = splitSpace(space);
        const id = rid();
        await putFile(ow, re, `drop/${tag}/${id}`, data, null);
        return id;
      },
      async list(space, tag) {
        const [ow, re] = splitSpace(space);
        const out: MailboxItem[] = [];
        for (const e of await listDir(ow, re, `drop/${tag}`, false)) {
          const f = await getFile(ow, re, e.path);
          if (f) out.push({ id: e.name, data: f.data });
        }
        return out;
      },
      async delete(space, tag, id) {
        const [ow, re] = splitSpace(space);
        const f = await getFile(ow, re, `drop/${tag}/${id}`);
        if (f) await deleteFile(ow, re, `drop/${tag}/${id}`, f.version);
      },
    },
    vault: {
      async get(name) {
        return getFile(login, homeRepo, `vault/${name}`);
      },
      async put(name, data, expected) {
        await ensureOwnRepo(homeRepo, true, 'Encrypted settings for an end-to-end encrypted chat app.');
        return putFile(login, homeRepo, `vault/${name}`, data, expected);
      },
    },
    personal: {
      async list() {
        return (await listDir(login, homeRepo, 'items', false)).map((e) => ({ id: e.name, version: e.sha }));
      },
      async get(id) {
        return getFile(login, homeRepo, `items/${id}`);
      },
      async put(id, data, expected) {
        await ensureOwnRepo(homeRepo, true, 'Encrypted settings for an end-to-end encrypted chat app.');
        return putFile(login, homeRepo, `items/${id}`, data, expected);
      },
      async delete(id, expected) {
        return deleteFile(login, homeRepo, `items/${id}`, expected);
      },
    },
    channel,
  };
}
