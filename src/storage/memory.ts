/**
 * In-memory reference provider. Enforces every access rule of every kind, so it doubles as
 * the executable specification that real providers are tested against (tests/conformance).
 * One `MemoryWorld` is the shared backend; `world.session(address)` is one signed-in user.
 */
import { own, randomBytes, toHex } from '../util/bytes.js';
import { KeyholdError } from '../util/errors.js';
import type {
  Address,
  Bytes,
  CasResult,
  Capability,
  ChannelAccess,
  DeviceKeystore,
  DeviceStorage,
  EphemeralKeyStore,
  GrantResult,
  InviteNotice,
  MailboxItem,
  ReceivedNotice,
  SpaceRef,
  StorageProvider,
  Versioned,
} from './interfaces.js';

const DAY = 86_400_000;
const rid = () => toHex(randomBytes(12));
const copy = (b: Bytes) => own(b);
const forbidden = (what: string) => new KeyholdError('forbidden', what);

interface Space {
  ref: SpaceRef;
  owner: Address;
  members: Set<Address>;
  pending: Map<string, Address>; // pointer -> invitee
  log: Bytes[];
  mail: MailboxItem[];
  blobs: Map<string, Bytes>;
  drop: Map<string, MailboxItem[]>;
}

export interface MemoryWorldOptions {
  /** Provide box 4 (claim-once). Default true. */
  claimOnce?: boolean;
  /** Only the creator may grant or revoke (like GitHub personal repos). Default false. */
  ownerManagedSpaces?: boolean;
  /** Max invite notices one sender may send per day. */
  inboxRateLimit?: number;
  now?: () => number;
}

export class MemoryWorld {
  readonly options: Required<Omit<MemoryWorldOptions, 'now'>>;
  readonly now: () => number;
  readonly directories = new Map<Address, Bytes[]>();
  readonly claims = new Map<Address, { data: Bytes; expiresAt: number }[]>();
  readonly inboxes = new Map<Address, ReceivedNotice[]>();
  readonly sent = new Map<Address, number[]>();
  readonly spaces = new Map<SpaceRef, Space>();
  readonly vaults = new Map<Address, Map<string, Versioned>>();
  readonly personal = new Map<Address, Map<string, Versioned>>();
  /** Count of calls per operation, for tests. */
  readonly calls = new Map<string, number>();

  constructor(options: MemoryWorldOptions = {}) {
    this.options = {
      claimOnce: options.claimOnce ?? true,
      ownerManagedSpaces: options.ownerManagedSpaces ?? false,
      inboxRateLimit: options.inboxRateLimit ?? 50,
    };
    this.now = options.now ?? Date.now;
  }

  count(op: string) {
    this.calls.set(op, (this.calls.get(op) ?? 0) + 1);
  }

  session(self: Address): StorageProvider {
    return memorySession(this, self);
  }

  /** Test hook: the storage operator rewrites history (like a force-push). */
  rewriteLog(space: SpaceRef, index: number, entry: Bytes) {
    this.spaces.get(space)!.log[index] = copy(entry);
  }

  rewriteDirectory(owner: Address, index: number, entry: Bytes) {
    this.directories.get(owner)![index] = copy(entry);
  }
}

function memorySession(w: MemoryWorld, self: Address): StorageProvider {
  const caps = new Set<Capability>(['inbox-payload', 'true-delete']);
  if (w.options.claimOnce) caps.add('claim-once');
  if (w.options.ownerManagedSpaces) caps.add('owner-managed-spaces');

  const space = (ref: SpaceRef): Space => {
    const s = w.spaces.get(ref);
    if (!s || !s.members.has(self)) throw forbidden(`${self} is not a member of ${ref}`);
    return s;
  };
  const mayManage = (s: Space) => (w.options.ownerManagedSpaces ? s.owner === self : s.members.has(self));
  const mine = <T>(m: Map<Address, T>, make: () => T): T => {
    let v = m.get(self);
    if (!v) m.set(self, (v = make()));
    return v;
  };
  const cas = (m: Map<string, Versioned>, id: string, data: Bytes, expected: string | null): CasResult => {
    const cur = m.get(id);
    if ((cur?.version ?? null) !== expected) return 'conflict';
    m.set(id, { data: copy(data), version: rid() });
    return 'ok';
  };

  const channel: ChannelAccess = {
    self,
    async createSpace() {
      w.count('createSpace');
      const ref = `mem:${rid()}`;
      w.spaces.set(ref, { ref, owner: self, members: new Set([self]), pending: new Map(), log: [], mail: [], blobs: new Map(), drop: new Map() });
      return ref;
    },
    async listSpaces() {
      return [...w.spaces.values()].filter((s) => s.members.has(self)).map((s) => s.ref);
    },
    async canManage(ref) {
      return mayManage(space(ref));
    },
    async members(ref) {
      const s = space(ref);
      return { active: [...s.members], pending: [...new Set(s.pending.values())] };
    },
    async grant(ref, address): Promise<GrantResult> {
      const s = space(ref);
      if (!mayManage(s)) return { status: 'needs-manager' };
      if (s.members.has(address)) return { status: 'already-member' };
      for (const [p, a] of s.pending) if (a === address) return { status: 'invited', pointer: p };
      const pointer = `${ref}#${rid()}`;
      s.pending.set(pointer, address);
      return { status: 'invited', pointer };
    },
    async acceptGrant(pointer) {
      const ref = pointer.split('#')[0]!;
      const s = w.spaces.get(ref);
      const who = s?.pending.get(pointer);
      if (!s || !who) return; // already accepted or withdrawn: harmless
      if (who !== self) throw forbidden('this invitation is for someone else');
      s.pending.delete(pointer);
      s.members.add(self);
    },
    async revoke(ref, address) {
      const s = space(ref);
      if (!mayManage(s)) return 'needs-manager';
      s.members.delete(address);
      for (const [p, a] of s.pending) if (a === address) s.pending.delete(p);
      return 'done';
    },
  };

  return {
    name: 'memory',
    capabilities: caps,
    limits: { maxBlobBytes: 100 * 1024 * 1024, maxItemBytes: 1024 * 1024 },
    directory: {
      async read(owner) {
        w.count('directory.read');
        return (w.directories.get(owner) ?? []).map(copy);
      },
      async append(index, entry) {
        const d = mine(w.directories, () => [] as Bytes[]);
        if (index !== d.length) return 'conflict';
        d.push(copy(entry));
        return 'ok';
      },
    },
    claimOnce: w.options.claimOnce
      ? {
          async publish(items, options) {
            const list = mine(w.claims, () => [] as { data: Bytes; expiresAt: number }[]);
            const expiresAt = options?.expiresAt ?? w.now() + 30 * DAY;
            for (const data of items) list.push({ data: copy(data), expiresAt });
          },
          async claim(owner) {
            const list = w.claims.get(owner) ?? [];
            const now = w.now();
            while (list.length) {
              const item = list.shift()!; // atomic in JS: no await between read and remove
              if (item.expiresAt > now) return item.data;
            }
            return undefined;
          },
          async remaining() {
            const now = w.now();
            return (w.claims.get(self) ?? []).filter((i) => i.expiresAt > now).length;
          },
        }
      : undefined,
    inviteInbox: {
      async send(to, notice: InviteNotice) {
        const now = w.now();
        const recent = (w.sent.get(self) ?? []).filter((t) => t > now - DAY);
        if (recent.length >= w.options.inboxRateLimit) throw new KeyholdError('too_many_attempts', 'invite rate limit reached');
        recent.push(now);
        w.sent.set(self, recent);
        const box = w.inboxes.get(to) ?? [];
        box.push({ id: rid(), from: self, pointer: notice.pointer, payload: notice.payload && copy(notice.payload), expiresAt: now + 7 * DAY });
        w.inboxes.set(to, box);
      },
      async list() {
        const now = w.now();
        return (w.inboxes.get(self) ?? []).filter((n) => n.expiresAt > now).map((n) => ({ ...n }));
      },
      async delete(id) {
        w.inboxes.set(self, (w.inboxes.get(self) ?? []).filter((n) => n.id !== id));
      },
    },
    orderedLog: {
      async read(ref, from) {
        w.count('log.read');
        return space(ref).log.slice(from).map(copy);
      },
      async append(ref, index, entry) {
        const s = space(ref);
        if (index !== s.log.length) return 'conflict';
        s.log.push(copy(entry));
        return 'ok';
      },
    },
    mailbox: {
      async post(ref, data) {
        const id = rid();
        space(ref).mail.push({ id, data: copy(data) });
        return id;
      },
      async list(ref, cursor) {
        const s = space(ref);
        const from = cursor ? Number(cursor) : 0;
        return { items: s.mail.slice(from).map((i) => ({ id: i.id, data: copy(i.data) })), cursor: String(s.mail.length) };
      },
    },
    blobs: {
      async put(ref, data) {
        if (data.length > 100 * 1024 * 1024) throw new KeyholdError('config', 'blob too large');
        const id = rid();
        space(ref).blobs.set(id, copy(data));
        return id;
      },
      async get(ref, id) {
        const b = space(ref).blobs.get(id);
        return b && copy(b);
      },
      async delete(ref, id) {
        space(ref).blobs.delete(id);
      },
    },
    dropBox: {
      async put(ref, tag, data) {
        const s = space(ref);
        const id = rid();
        const list = s.drop.get(tag) ?? [];
        list.push({ id, data: copy(data) });
        s.drop.set(tag, list);
        return id;
      },
      async list(ref, tag) {
        return (space(ref).drop.get(tag) ?? []).map((i) => ({ id: i.id, data: copy(i.data) }));
      },
      async delete(ref, tag, id) {
        const s = space(ref);
        s.drop.set(tag, (s.drop.get(tag) ?? []).filter((i) => i.id !== id));
      },
    },
    vault: {
      async get(name) {
        const v = w.vaults.get(self)?.get(name);
        return v && { data: copy(v.data), version: v.version };
      },
      async put(name, data, expected) {
        return cas(mine(w.vaults, () => new Map()), name, data, expected);
      },
    },
    personal: {
      async list() {
        w.count('personal.list');
        return [...(w.personal.get(self) ?? new Map<string, Versioned>()).entries()].map(([id, v]) => ({ id, version: v.version }));
      },
      async get(id) {
        const v = w.personal.get(self)?.get(id);
        return v && { data: copy(v.data), version: v.version };
      },
      async put(id, data, expected) {
        w.count('personal.put');
        return cas(mine(w.personal, () => new Map()), id, data, expected);
      },
      async delete(id, expected) {
        const m = mine(w.personal, () => new Map<string, Versioned>());
        if (m.get(id)?.version !== expected) return 'conflict';
        m.delete(id);
        return 'ok';
      },
    },
    channel,
  };
}

// ---- Device-side stores (boxes 1, 2) in memory ------------------------------------------------

export class MemoryKeystore implements DeviceKeystore {
  private m = new Map<string, Bytes>();
  async get(k: string) {
    const v = this.m.get(k);
    return v && copy(v);
  }
  async put(k: string, v: Bytes) {
    this.m.set(k, copy(v));
  }
  async delete(k: string) {
    this.m.get(k)?.fill(0);
    this.m.delete(k);
  }
  async keys(prefix = '') {
    return [...this.m.keys()].filter((k) => k.startsWith(prefix));
  }
}

export class MemoryEphemeralStore implements EphemeralKeyStore {
  private m = new Map<string, { v: Bytes; exp?: number }>();
  constructor(private now: () => number = Date.now) {}
  async get(k: string) {
    const e = this.m.get(k);
    if (!e) return undefined;
    if (e.exp !== undefined && e.exp <= this.now()) {
      await this.delete(k);
      return undefined;
    }
    return copy(e.v);
  }
  async put(k: string, v: Bytes, o?: { expiresAt?: number }) {
    await this.delete(k);
    this.m.set(k, { v: copy(v), exp: o?.expiresAt });
  }
  async take(k: string) {
    const v = await this.get(k);
    await this.delete(k);
    return v;
  }
  async delete(k: string) {
    this.m.get(k)?.v.fill(0); // wipe before dropping the reference
    this.m.delete(k);
  }
  async purgeExpired(now = this.now()) {
    let n = 0;
    for (const [k, e] of this.m) if (e.exp !== undefined && e.exp <= now) (await this.delete(k), n++);
    return n;
  }
  async keys(prefix = '') {
    return [...this.m.keys()].filter((k) => k.startsWith(prefix));
  }
  /** For tests: raw size. */
  get size() {
    return this.m.size;
  }
}

export function memoryDevice(now?: () => number): DeviceStorage & { ephemeral: MemoryEphemeralStore } {
  return { keystore: new MemoryKeystore(), ephemeral: new MemoryEphemeralStore(now) };
}
