/**
 * Personal synced store (box 12): contacts, chat list, read marks, block list, settings,
 * drafts and the message history backup. Only you, on all your devices.
 *
 * - Every item is sealed with the account key K (keyhold/crypto), bound to its opaque id.
 * - Ids are HMACs of the logical key under an index key that is itself sealed with K, so the
 *   storage can't tell a contact from a read mark, or count your contacts by name.
 * - Concurrent edits merge per field, so devices never fork: whatever order writes land in,
 *   every device ends up with the same record. Each field has a merge rule: last writer wins
 *   (default; hybrid clock, device id breaks ties), `max` (the larger number wins, for marks
 *   that only move forward), or `once` (the first value set wins and can't be cleared, for
 *   tombstones such as "this chat ended").
 *   Writes are queued and flushed in one pass, so frequent changes (read marks) cost one write
 *   per item per flush.
 */
import { randomBytes, toBase64Url } from '../util/bytes.js';
import { canonicalJson, jsonBytes, parseJsonBytes } from '../util/codec.js';
import { KeyholdError } from '../util/errors.js';
import { open, seal } from '../crypto/index.js';
import type { Address, DeviceKeystore, PersonalStore } from '../storage/interfaces.js';
import { mayBackUp } from '../storage/requirements.js';
import type { Pin, PinStore } from './identity.js';

type Stamp = { t: number; d: string };
/** How concurrent values of one field combine. */
export type MergeRule = 'lww' | 'max' | 'once';
type Field = { v: unknown; t: number; d: string; m?: MergeRule };
interface Item {
  c: string;
  k: string;
  f: Record<string, Field>;
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
/** Device copies (box 1), see `PersonalOptions.local`. */
const LOCAL_INDEX = 'personal/index';
const LOCAL_ITEM = 'personal/item/';
/** Collections not copied to the device: large, and only for restoring other devices. */
const NOT_LOCAL = new Set<string>(['history']);

export interface PersonalOptions {
  /**
   * This device's keystore (box 1). With it, every record (except the history backup) is also
   * kept on the device, sealed with K, and merged with what the store returns. The storage
   * operator can then no longer roll a record back or delete it unnoticed: what this device
   * already knew is merged back in and written again by the next flush (`repairs` counts
   * them). This matters most for the TOFU pins kept with contacts (see `pinStore`): without a
   * device copy, deleting a contact record resets trust in that person's key. Recommended.
   */
  local?: DeviceKeystore;
}
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
  /**
   * Changes taken out of the queue by a flush and being written now. A `set()` during the write
   * goes into a fresh queue entry, so it is written by the next flush instead of being lost.
   */
  private writing = new Map<string, Item>();
  /** Flushes run one after another. */
  private flushing: Promise<unknown> = Promise.resolve();
  private cache = new Map<string, { item: Item; version: string }>();
  /** Versions already seen by `changes()`. */
  private seen = new Map<string, string>();
  private clock = 0;
  /** Records the store returned older than this device's copy (or not at all), since open. */
  repairs = 0;

  private constructor(
    private store: PersonalStore,
    private key: CryptoKey,
    private indexKey: CryptoKey,
    private deviceId: string,
    private now: () => number,
    private local?: DeviceKeystore,
  ) {}

  static async open(store: PersonalStore, key: CryptoKey, deviceId: string, now: () => number = Date.now, options: PersonalOptions = {}): Promise<PersonalData> {
    const ctx = { type: 'personal-index' };
    const local = options.local;
    // The index key never changes once made. If the store lost it, the device copy puts it back
    // (a new one would make every record unreachable, pins included).
    const kept = local ? await local.get(LOCAL_INDEX) : undefined;
    for (let attempt = 0; attempt < 5; attempt++) {
      const cur = await store.get(INDEX_ID);
      let raw: Uint8Array<ArrayBuffer>;
      if (cur) raw = await open(key, cur.data, ctx);
      else {
        raw = kept ? await open(key, kept, ctx) : randomBytes(32);
        if ((await store.put(INDEX_ID, await seal(key, raw, ctx), null)) !== 'ok') continue; // another device made it first
      }
      if (local) await local.put(LOCAL_INDEX, await seal(key, raw, ctx));
      const indexKey = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      raw.fill(0);
      return new PersonalData(store, key, indexKey, deviceId, now, local);
    }
    throw new KeyholdError('conflict', 'could not set up the personal store');
  }

  private async readLocal(id: string): Promise<Item | undefined> {
    const b = this.local ? await this.local.get(LOCAL_ITEM + id) : undefined;
    return b ? parseJsonBytes<Item>(await open(this.key, b, this.ctx(id))) : undefined;
  }

  private async writeLocal(id: string, item: Item) {
    if (!this.local || NOT_LOCAL.has(item.c)) return;
    await this.local.put(LOCAL_ITEM + id, await seal(this.key, jsonBytes(item), this.ctx(id), { compress: true }));
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
    const remote = v ? parseJsonBytes<Item>(await open(this.key, v.data, this.ctx(id))) : undefined;
    const kept = await this.readLocal(id);
    const item = merge(remote, kept);
    if (!item) return undefined;
    for (const f of Object.values(item.f)) this.clock = Math.max(this.clock, f.t);
    if (kept && (!remote || canonicalJson(merge(remote, undefined)) !== canonicalJson(item))) {
      // The store is behind what this device knew (rolled back, or the record deleted):
      // write what we know back with the next flush. Merging is order-free, so this is safe.
      this.repairs++;
      this.queue.set(id, merge(kept, this.queue.get(id))!);
    }
    if (remote && canonicalJson(merge(remote, undefined)) !== canonicalJson(kept ?? null)) await this.writeLocal(id, item);
    const entry = { item, version: v?.version ?? '' };
    this.cache.set(id, entry);
    return entry;
  }

  /** Record ids in the store and, with a device copy, those this device knows of. */
  private async ids(): Promise<{ id: string; version: string }[]> {
    const listed = await this.store.list();
    if (!this.local) return listed;
    const have = new Set(listed.map((x) => x.id));
    const extra = (await this.local.keys(LOCAL_ITEM)).map((k) => k.slice(LOCAL_ITEM.length)).filter((id) => !have.has(id));
    return [...listed, ...extra.map((id) => ({ id, version: '' }))];
  }

  /**
   * Queue a change to some fields. Call `flush()` to write. `undefined` deletes a field
   * (not for `once` fields). `rules` picks the merge rule per field; the default is last writer wins.
   */
  async set(collection: Collection, key: string, fields: Record<string, unknown>, rules: Record<string, MergeRule> = {}) {
    if (!mayBackUp(COLLECTION_TYPE[collection])) throw new KeyholdError('config', `${collection} may not be stored off-device`);
    const id = await this.idFor(collection, key);
    const s = this.stamp();
    const q = this.queue.get(id) ?? { c: collection, k: key, f: {} };
    for (const [name, v] of Object.entries(fields)) {
      const m = rules[name];
      const f: Field = { v: v === undefined ? null : v, t: s.t, d: s.d, ...(m && m !== 'lww' ? { m } : {}) };
      q.f[name] = q.f[name] ? pick(q.f[name]!, f) : f;
    }
    this.queue.set(id, q);
  }

  /** Records with changes not yet written (queued, or being written by a flush in progress). */
  get pending() {
    return new Set([...this.queue.keys(), ...this.writing.keys()]).size;
  }

  /** Whether this record has changes not yet written (queued, or being written right now). */
  async isPending(collection: Collection, key: string): Promise<boolean> {
    const id = await this.idFor(collection, key);
    return this.queue.has(id) || this.writing.has(id);
  }

  /**
   * Records that changed in storage since the last call (the first call returns everything).
   * One listing, then a read only for items whose version changed: cheap enough to poll.
   */
  async changes(): Promise<{ collection: Collection; key: string; value: Record<string, unknown> }[]> {
    const out: { collection: Collection; key: string; value: Record<string, unknown> }[] = [];
    for (const { id, version } of await this.ids()) {
      if (id === INDEX_ID || (version !== '' && this.seen.get(id) === version) || (version === '' && this.seen.has(id))) continue;
      const e = await this.load(id);
      if (!e) continue;
      this.seen.set(id, e.version);
      const v = await this.get(e.item.c as Collection, e.item.k, false);
      out.push({ collection: e.item.c as Collection, key: e.item.k, value: v ?? {} });
    }
    return out;
  }

  /** Read one record (including queued, unflushed changes). Fields set to null are absent. */
  async get<T extends object = Record<string, unknown>>(collection: Collection, key: string, fresh = true): Promise<T | undefined> {
    const id = await this.idFor(collection, key);
    const base = fresh ? await this.load(id) : this.cache.get(id) ?? (await this.load(id));
    const merged = merge(merge(base?.item, this.writing.get(id)), this.queue.get(id));
    if (!merged) return undefined;
    const out: Record<string, unknown> = {};
    for (const [k, f] of Object.entries(merged.f)) if (f.v !== null) out[k] = f.v;
    return Object.keys(out).length ? (out as T) : undefined;
  }

  /** All records of a collection. Reads every item: fine for small collections. */
  async list<T extends object = Record<string, unknown>>(collection: Collection): Promise<{ key: string; value: T }[]> {
    const out: { key: string; value: T }[] = [];
    for (const { id } of await this.ids()) {
      if (id === INDEX_ID) continue;
      const e = await this.load(id);
      if (!e || e.item.c !== collection) continue;
      const v = await this.get<T>(collection, e.item.k, false);
      if (v) out.push({ key: e.item.k, value: v });
    }
    return out;
  }

  /**
   * Write queued changes, merging with whatever other devices wrote meanwhile. Changes made
   * while a flush runs stay queued for the next one (`pending` counts them). Resolves to the
   * number of writes.
   */
  flush(): Promise<number> {
    const run = this.flushing.then(
      () => this.flushNow(),
      () => this.flushNow(),
    );
    this.flushing = run.catch(() => undefined);
    return run;
  }

  private async flushNow(): Promise<number> {
    let writes = 0;
    for (const id of [...this.queue.keys()]) {
      const q = this.queue.get(id);
      if (!q) continue;
      // Take the entry out before writing: a set() from now on starts a new one.
      this.queue.delete(id);
      this.writing.set(id, q);
      try {
        for (let attempt = 0; ; attempt++) {
          if (attempt > 8) throw new KeyholdError('conflict', 'personal store kept changing');
          const v = await this.store.get(id);
          const cur = v ? parseJsonBytes<Item>(await open(this.key, v.data, this.ctx(id))) : undefined;
          const merged = merge(merge(cur, await this.readLocal(id)), q)!;
          const sealed = await seal(this.key, jsonBytes(merged), this.ctx(id), { compress: true });
          if ((await this.store.put(id, sealed, v?.version ?? null)) === 'ok') {
            writes++;
            await this.writeLocal(id, merged);
            this.cache.delete(id); // its version changed; read it again when needed
            break;
          }
        }
      } catch (e) {
        // Not written: back into the queue, together with anything set meanwhile (merging is order-free).
        this.queue.set(id, merge(q, this.queue.get(id))!);
        throw e;
      } finally {
        this.writing.delete(id);
      }
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

/**
 * Pick the surviving value of one field. A total order for each rule, so the result doesn't
 * depend on which device writes first (commutative, associative, idempotent: no forks).
 */
export function pick(a: Field, b: Field): Field {
  const rule = a.m === 'once' || b.m === 'once' ? 'once' : a.m === 'max' || b.m === 'max' ? 'max' : 'lww';
  if (rule === 'once') {
    if (a.v === null || a.v === undefined) return b.v === null || b.v === undefined ? (later(a, b) ? a : b) : b;
    if (b.v === null || b.v === undefined) return a;
    return later(a, b) ? b : a; // the earliest non-empty value stays
  }
  if (rule === 'max' && typeof a.v === 'number' && typeof b.v === 'number' && a.v !== b.v) return a.v > b.v ? a : b;
  return later(b, a) ? b : a;
}

function merge(a: Item | undefined, b: Item | undefined): Item | undefined {
  if (!a) return b && { ...b, f: { ...b.f } };
  if (!b) return { ...a, f: { ...a.f } };
  const f = { ...a.f };
  for (const [k, v] of Object.entries(b.f)) {
    const cur = f[k];
    f[k] = cur ? pick(cur, v) : v;
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
