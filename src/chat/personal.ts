/**
 * Personal synced store (box 12): contacts, chat list, read marks, block list, settings,
 * drafts and the message history backup. Only you, on all your devices.
 *
 * - Every item is sealed with the account key K (keyhold/crypto), bound to its opaque id.
 * - Ids are HMACs of the logical key under an index key that is itself sealed with K, so the
 *   storage can't tell a contact from a read mark, or count your contacts by name.
 * - Concurrent edits merge per field, last writer wins (hybrid clock, device id breaks ties).
 *   Writes are queued and flushed in one pass, so frequent changes (read marks) cost one write
 *   per item per flush.
 */
import { randomBytes, toBase64Url } from '../util/bytes.js';
import { jsonBytes, parseJsonBytes } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import { open, seal } from '../crypto/index.js';
import type { Address, PersonalStore } from '../storage/interfaces.js';
import { mayBackUp } from '../storage/requirements.js';
import type { Pin, PinStore } from './identity.js';

type Stamp = { t: number; d: string };
interface Item {
  c: string;
  k: string;
  f: Record<string, { v: unknown; t: number; d: string }>;
}

export type Collection = 'contacts' | 'chats' | 'readMarks' | 'blocks' | 'settings' | 'drafts' | 'history';

/** Which data type each collection is (so the backup rule can be checked). */
const COLLECTION_TYPE: Record<Collection, string> = {
  contacts: 'contacts',
  chats: 'chat-list',
  readMarks: 'read-marks',
  blocks: 'block-list',
  settings: 'settings',
  drafts: 'drafts',
  history: 'history-backup',
};

const INDEX_ID = 'i';
const later = (a: Stamp, b: Stamp) => a.t > b.t || (a.t === b.t && a.d > b.d);

export interface ContactRecord {
  fingerprint?: string;
  pinIndex?: number;
  pinHash?: string;
  verified?: boolean;
  nickname?: string;
}

export interface ChatRecord {
  space?: string;
  pinned?: boolean;
  muted?: boolean;
  archived?: boolean;
}

export interface HistoryRecord {
  id: string;
  from: string;
  ts: number;
  body: unknown;
}

export class PersonalData {
  private queue = new Map<string, Item>();
  private cache = new Map<string, { item: Item; version: string }>();
  private clock = 0;

  private constructor(
    private store: PersonalStore,
    private key: CryptoKey,
    private indexKey: CryptoKey,
    private deviceId: string,
    private now: () => number,
  ) {}

  static async open(store: PersonalStore, key: CryptoKey, deviceId: string, now: () => number = Date.now): Promise<PersonalData> {
    const ctx = { type: 'personal-index' };
    for (let attempt = 0; attempt < 5; attempt++) {
      const cur = await store.get(INDEX_ID);
      let raw: Uint8Array<ArrayBuffer>;
      if (cur) raw = await open(key, cur.data, ctx);
      else {
        raw = randomBytes(32);
        if ((await store.put(INDEX_ID, await seal(key, raw, ctx), null)) !== 'ok') continue; // another device made it first
      }
      const indexKey = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      raw.fill(0);
      return new PersonalData(store, key, indexKey, deviceId, now);
    }
    throw new KeyholdError('conflict', 'could not set up the personal store');
  }

  private stamp(): Stamp {
    this.clock = Math.max(this.now(), this.clock + 1);
    return { t: this.clock, d: this.deviceId };
  }

  private async idFor(c: string, k: string) {
    const mac = await crypto.subtle.sign('HMAC', this.indexKey, jsonBytes([c, k]));
    return toBase64Url(new Uint8Array(mac).subarray(0, 18));
  }

  private ctx(id: string) {
    return { type: 'personal', id };
  }

  private async load(id: string): Promise<{ item: Item; version: string } | undefined> {
    const v = await this.store.get(id);
    if (!v) return undefined;
    const item = parseJsonBytes<Item>(await open(this.key, v.data, this.ctx(id)));
    for (const f of Object.values(item.f)) this.clock = Math.max(this.clock, f.t);
    const entry = { item, version: v.version };
    this.cache.set(id, entry);
    return entry;
  }

  /** Queue a change to some fields. Call `flush()` to write. `undefined` deletes a field. */
  async set(collection: Collection, key: string, fields: Record<string, unknown>) {
    if (!mayBackUp(COLLECTION_TYPE[collection])) throw new KeyholdError('config', `${collection} may not be stored off-device`);
    const id = await this.idFor(collection, key);
    const s = this.stamp();
    const q = this.queue.get(id) ?? { c: collection, k: key, f: {} };
    for (const [name, v] of Object.entries(fields)) q.f[name] = { v: v === undefined ? null : v, t: s.t, d: s.d };
    this.queue.set(id, q);
  }

  /** Read one record (including queued, unflushed changes). Fields set to null are absent. */
  async get<T extends object = Record<string, unknown>>(collection: Collection, key: string, fresh = true): Promise<T | undefined> {
    const id = await this.idFor(collection, key);
    const base = fresh ? await this.load(id) : this.cache.get(id) ?? (await this.load(id));
    const merged = merge(base?.item, this.queue.get(id));
    if (!merged) return undefined;
    const out: Record<string, unknown> = {};
    for (const [k, f] of Object.entries(merged.f)) if (f.v !== null) out[k] = f.v;
    return Object.keys(out).length ? (out as T) : undefined;
  }

  /** All records of a collection. Reads every item: fine for small collections. */
  async list<T extends object = Record<string, unknown>>(collection: Collection): Promise<{ key: string; value: T }[]> {
    const out: { key: string; value: T }[] = [];
    for (const { id } of await this.store.list()) {
      if (id === INDEX_ID) continue;
      const e = await this.load(id);
      if (!e || e.item.c !== collection) continue;
      const v = await this.get<T>(collection, e.item.k, false);
      if (v) out.push({ key: e.item.k, value: v });
    }
    return out;
  }

  /** Write queued changes, merging with whatever other devices wrote meanwhile. */
  async flush(): Promise<number> {
    let writes = 0;
    for (const [id, q] of [...this.queue]) {
      for (let attempt = 0; ; attempt++) {
        if (attempt > 8) throw new KeyholdError('conflict', 'personal store kept changing');
        const cur = await this.load(id);
        const merged = merge(cur?.item, q)!;
        const sealed = await seal(this.key, jsonBytes(merged), this.ctx(id), { compress: true });
        if ((await this.store.put(id, sealed, cur?.version ?? null)) === 'ok') {
          writes++;
          break;
        }
      }
      this.queue.delete(id);
    }
    return writes;
  }

  // ---- Typed helpers ----

  contact(address: Address) {
    return this.get<ContactRecord>('contacts', address);
  }
  setContact(address: Address, c: ContactRecord) {
    return this.set('contacts', address, c as Record<string, unknown>);
  }
  setChat(groupId: string, c: ChatRecord) {
    return this.set('chats', groupId, c as Record<string, unknown>);
  }
  setReadMark(groupId: string, messageId: string) {
    return this.set('readMarks', groupId, { at: messageId });
  }
  block(address: Address, blocked = true) {
    return this.set('blocks', address, { blocked: blocked || undefined });
  }
  setting(name: string, value: unknown) {
    return this.set('settings', name, { value });
  }

  /**
   * Message history backup, for new devices. Each device writes its own batches, so batches
   * never conflict. Only decrypted messages go here, never keys (rule: no box 2 data in backups).
   */
  async backupHistory(groupId: string, records: HistoryRecord[]) {
    if (records.length === 0) return;
    await this.set('history', `${groupId}:${this.deviceId}:${this.stamp().t}`, { g: groupId, m: records });
  }

  async readHistory(groupId: string): Promise<HistoryRecord[]> {
    const seen = new Map<string, HistoryRecord>();
    for (const { value } of await this.list<{ g: string; m: HistoryRecord[] }>('history')) {
      if (value.g !== groupId) continue;
      for (const r of value.m) seen.set(r.id, r);
    }
    return [...seen.values()].sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : 1));
  }

  /** TOFU pins kept with contacts, so every device trusts the same keys. */
  pinStore(): PinStore {
    return {
      get: async (address) => {
        const c = await this.contact(address);
        return c?.fingerprint ? ({ fingerprint: c.fingerprint, index: c.pinIndex ?? 0, hash: c.pinHash ?? '', verified: c.verified } as Pin) : undefined;
      },
      set: async (address, pin) => {
        await this.setContact(address, { fingerprint: pin.fingerprint, pinIndex: pin.index, pinHash: pin.hash, verified: pin.verified });
        await this.flush();
      },
    };
  }
}

function merge(a: Item | undefined, b: Item | undefined): Item | undefined {
  if (!a) return b && { ...b, f: { ...b.f } };
  if (!b) return { ...a, f: { ...a.f } };
  const f = { ...a.f };
  for (const [k, v] of Object.entries(b.f)) {
    const cur = f[k];
    if (!cur || later(v, cur)) f[k] = v;
  }
  return { c: a.c, k: a.k, f };
}

/**
 * Device approval relay over the personal store. The approval messages are already protected
 * end to end by keyhold/keys approval (ECDH + words), so they are stored as-is and deleted after.
 */
export function approvalRelay(store: PersonalStore) {
  const id = (session: string, kind: string) => `r.${session}.${kind}`;
  return {
    async send(session: string, kind: 'hello' | 'key', message: unknown) {
      await store.put(id(session, kind), jsonBytes(message), null);
    },
    async receive<T>(session: string, kind: 'hello' | 'key'): Promise<T | undefined> {
      const v = await store.get(id(session, kind));
      if (!v) return undefined;
      await store.delete(id(session, kind), v.version);
      return parseJsonBytes<T>(v.data);
    },
  };
}

/**
 * Wire the history backup to a chat client: pass `onMessage` to Chat.open and call `flush()`
 * now and then (for example after each sync). Batches per group, one write per flush.
 */
export function historyRecorder(personal: PersonalData, enabled = true) {
  const queue = new Map<string, HistoryRecord[]>();
  return {
    onMessage(group: { id: string }, m: { message: { id: string; ts: number }; from: { fingerprint: string } }) {
      if (!enabled) return;
      const list = queue.get(group.id) ?? [];
      list.push({ id: m.message.id, from: m.from.fingerprint, ts: m.message.ts, body: m.message });
      queue.set(group.id, list);
    },
    async flush() {
      for (const [g, records] of queue) await personal.backupHistory(g, records);
      queue.clear();
      return personal.flush();
    },
  };
}
