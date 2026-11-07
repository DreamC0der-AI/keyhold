/**
 * One signed-in account in this browser: Keyhold chat over the GitHub provider, the local
 * stores, and a polling loop that keeps chats up to date without burning the rate limit.
 */
import { githubProvider, toAddress, loginOf } from '@keyhold/providers/github/index';
import type { FetchFn } from '@keyhold/providers/github/client';
import { resolveFeatures } from '@keyhold/storage/features';
import type { DeviceStorage, StorageProvider } from '@keyhold/storage/interfaces';
import {
  Chat,
  createDeviceIdentity,
  createRootKey,
  DirectoryWriter,
  IdentityRegistry,
  loadDeviceIdentity,
  newDeviceId,
  safetyNumber,
  verifyDirectory,
  wipeRoot,
  fingerprint,
  backupRootKey,
  restoreRootKey,
  type DeviceIdentity,
  type Group,
  type GroupEvent,
  type ReceivedMessage,
  type RootKey,
  type DeviceCertificate,
  type LookupResult,
} from '@keyhold/chat/index';
import type { AttachmentRef } from '@keyhold/chat/messages';
import { generateRecoveryCode, parseRecoveryCode } from '@keyhold/keys/recovery';
import { hkdfAesKey } from '@keyhold/util/hkdf';
import { CONFIG } from '../config';
import { currentToken, type AuthState } from './auth';
import { Db, IdbPinStore, idbDevice } from './idb';

export type Phase = 'loading' | 'install' | 'new-identity' | 'restore' | 'ready' | 'error';

export interface MsgRecord {
  groupId: string;
  id: string;
  ts: number;
  from: string;
  fromFp: string;
  mine: boolean;
  kind: 'text' | 'attachment' | 'system';
  body?: string;
  file?: AttachmentRef;
  caption?: string;
  edited?: boolean;
  deleted?: boolean;
  reactions?: Record<string, string[]>;
  reply?: string;
}

export interface ChatRecord {
  groupId: string;
  invited: string[];
  createdAt: number;
  lastTs: number;
  lastText?: string;
  unread: number;
  hidden?: boolean;
  lastName?: string;
  deviceCount?: number;
}

export interface PeerInfo {
  address: string;
  status: LookupResult['status'] | 'error';
  fingerprint?: string;
  safety?: string;
  verified?: boolean;
  error?: string;
}

const ROOT_BACKUP_INFO = 'keyhold-chat-web/v1/root-backup';
const ACTIVE_POLL_MS = 4_000;
const IDLE_POLL_MS = 20_000;
const WARM_POLL_MS = 6_000;
const HIDDEN_POLL_MS = 90_000;
const INVITE_POLL_MS = 15_000;
const JOIN_RETRY_MS = 3 * 60_000;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const loginFrom = (address: string) => {
  try {
    return loginOf(address);
  } catch {
    return address;
  }
};

export function describeError(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  if (/rate limit/i.test(m)) return 'GitHub rate limit reached. Wait a few minutes and try again.';
  return m;
}

export class Session {
  phase: Phase = 'loading';
  error?: string;
  readonly address: string;
  readonly login: string;
  db!: Db;
  device!: DeviceStorage;
  provider!: StorageProvider & { client: { requests: number } };
  registry!: IdentityRegistry;
  identity?: DeviceIdentity;
  chat?: Chat;
  records = new Map<string, ChatRecord>();
  groupErrors = new Map<string, string>();
  rateRemaining?: number;
  activeGroup?: string;
  lastPollError?: string;
  /** Message ids being sent, per group, for the "sending…" bubble. */
  sending = new Map<string, { id: string; body: string; ts: number }[]>();

  private version = 0;
  private listeners = new Set<() => void>();
  private stopped = false;
  private lastCheck = new Map<string, number>();
  private etags = new Map<string, string>();
  private lastInvites = 0;
  private lastSpaceScan = 0;
  private joinTried = new Map<string, number>();
  private kick?: () => void;
  private peers = new Map<string, Promise<PeerInfo>>();

  constructor(readonly auth: AuthState) {
    this.login = auth.login.toLowerCase();
    this.address = toAddress(this.login);
  }

  // ---- store plumbing (React subscribes with useSyncExternalStore) ----

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };
  getVersion = () => this.version;
  bump() {
    this.version++;
    for (const l of this.listeners) l();
  }

  // ---- GitHub access ----

  /** fetch with the current (refreshed) token, no HTTP cache, and rate-limit tracking. */
  ghFetch = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
    const go = async (force: boolean) => {
      const token = await currentToken(force);
      return fetch(url, { ...init, headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}` }, cache: 'no-store' });
    };
    let r = await go(false);
    if (r.status === 401) r = await go(true);
    const left = r.headers.get('x-ratelimit-remaining');
    if (left !== null && url.startsWith(CONFIG.api)) this.rateRemaining = Number(left);
    return r;
  };

  private async ghJson<T>(path: string): Promise<{ status: number; data?: T }> {
    const r = await this.ghFetch(CONFIG.api + path, { headers: { Accept: 'application/vnd.github+json' } });
    const t = await r.text();
    return { status: r.status, data: t ? (JSON.parse(t) as T) : undefined };
  }

  // ---- start-up ----

  async start() {
    try {
      this.db = await Db.open(`keyhold-chat:${this.auth.id}`);
      this.device = idbDevice(this.db);
      this.provider = githubProvider({
        fetch: this.ghFetch as unknown as FetchFn,
        token: 'set-per-request',
        login: this.login,
        workerUrl: CONFIG.worker,
        apiBase: CONFIG.api,
        directoryRepo: CONFIG.directoryRepo,
        homeRepo: CONFIG.homeRepo,
        chatPrefix: CONFIG.chatPrefix,
        description: `End-to-end encrypted chat data. Only the members' chat app can read it. Open it at ${location.origin}`,
      });
      this.registry = new IdentityRegistry(this.provider.directory, new IdbPinStore(this.db));
      await this.decidePhase();
    } catch (e) {
      this.phase = 'error';
      this.error = describeError(e);
    }
    this.bump();
  }

  async decidePhase() {
    if (!(await this.isInstalled())) {
      this.phase = 'install';
      return;
    }
    this.identity = await loadDeviceIdentity(this.device);
    if (this.identity) {
      await this.openChat();
      return;
    }
    const dir = await verifyDirectory(await this.provider.directory.read(this.address));
    this.phase = dir ? 'restore' : 'new-identity';
  }

  async recheckInstall() {
    this.phase = 'loading';
    this.bump();
    try {
      await this.decidePhase();
    } catch (e) {
      this.phase = 'error';
      this.error = describeError(e);
    }
    this.bump();
  }

  async isInstalled(): Promise<boolean> {
    const r = await this.ghJson<{ installations: { account: { login: string } }[] }>('/user/installations?per_page=100');
    if (r.status !== 200) throw new Error(`Could not check the app installation (${r.status})`);
    return (r.data?.installations ?? []).some((i) => i.account.login.toLowerCase() === this.login);
  }

  // ---- identity ----

  private async recoveryKey(bytes: Uint8Array) {
    return hkdfAesKey(bytes, ROOT_BACKUP_INFO, ['encrypt', 'decrypt']);
  }

  /** Make a new identity. Returns the recovery code to show once. */
  async createIdentity(): Promise<string> {
    const root = createRootKey();
    try {
      const code = await generateRecoveryCode();
      // Back up first, so there is never a published identity without a way back in.
      await backupRootKey(this.provider.vault, await this.recoveryKey(code.bytes), this.address, root);
      const id = await createDeviceIdentity(this.device, root, this.address, newDeviceId());
      try {
        await new DirectoryWriter(this.provider.directory, this.address).publish(root, id.cert, { name: this.login });
      } catch (e) {
        await this.device.keystore.delete('chat/device-identity');
        throw e;
      }
      this.identity = id;
      return code.grouped;
    } finally {
      wipeRoot(root);
    }
  }

  async finishSetup() {
    await this.openChat();
    this.bump();
  }

  private async unlockRoot(codeText: string): Promise<RootKey> {
    const code = await parseRecoveryCode(codeText);
    let root: RootKey | undefined;
    try {
      root = await restoreRootKey(this.provider.vault, await this.recoveryKey(code.bytes), this.address);
    } catch {
      throw new Error('That recovery code does not open your backup.');
    }
    if (!root) throw new Error('No backup was found for this account.');
    const dir = await verifyDirectory(await this.provider.directory.read(this.address));
    if (dir && dir.fingerprint !== fingerprint(root.publicKey)) {
      wipeRoot(root);
      throw new Error('The backup does not match your published identity.');
    }
    return root;
  }

  /** Add this browser as a new device of an existing identity. */
  async restoreIdentity(codeText: string) {
    const root = await this.unlockRoot(codeText);
    try {
      const id = await createDeviceIdentity(this.device, root, this.address, newDeviceId());
      try {
        await new DirectoryWriter(this.provider.directory, this.address).addDevice(root, id.cert);
      } catch (e) {
        await this.device.keystore.delete('chat/device-identity');
        throw e;
      }
      this.identity = id;
    } finally {
      wipeRoot(root);
    }
    await this.openChat();
    this.bump();
  }

  async myDevices(): Promise<{ cert: DeviceCertificate; current: boolean }[]> {
    const dir = await verifyDirectory(await this.provider.directory.read(this.address));
    if (!dir) return [];
    return [...dir.devices.values()]
      .sort((a, b) => a.issuedAt - b.issuedAt)
      .map((cert) => ({ cert, current: !!this.identity && cert.deviceId === this.identity.deviceId }));
  }

  async revokeDevice(devicePublic: string, codeText: string) {
    const root = await this.unlockRoot(codeText);
    try {
      await new DirectoryWriter(this.provider.directory, this.address).revokeDevice(root, devicePublic);
    } finally {
      wipeRoot(root);
    }
  }

  /** Testing aid: delete the identity repos so the account can start fresh. */
  async resetIdentity() {
    this.stop();
    for (const name of [CONFIG.directoryRepo, CONFIG.homeRepo]) {
      const r = await this.ghFetch(`${CONFIG.api}/repos/${this.login}/${name}`, { method: 'DELETE', headers: { Accept: 'application/vnd.github+json' } });
      if (![204, 404].includes(r.status)) throw new Error(`Could not delete ${name} (${r.status})`);
    }
    this.db.close();
    await Db.delete(this.db.name);
  }

  async forgetBrowser() {
    this.stop();
    this.db.close();
    await Db.delete(this.db.name);
  }

  // ---- chats ----

  private async openChat() {
    this.chat = await Chat.open({
      provider: this.provider,
      device: this.device,
      identity: this.identity!,
      registry: this.registry,
      features: resolveFeatures(this.provider, { historyBackup: false }),
      onMessage: (g, m) => this.onMessage(g, m),
    });
    for (const k of await this.db.keys('kv', 'chat:')) {
      const r = await this.db.get<ChatRecord>('kv', k);
      if (r) this.records.set(r.groupId, r);
    }
    for (const g of this.chat.groups.values()) this.record(g.id);
    this.phase = 'ready';
    void this.loop();
  }

  record(groupId: string): ChatRecord {
    let r = this.records.get(groupId);
    if (!r) {
      r = { groupId, invited: [], createdAt: Date.now(), lastTs: Date.now(), unread: 0 };
      this.records.set(groupId, r);
      void this.saveRecord(r);
    }
    return r;
  }
  private saveRecord(r: ChatRecord) {
    return this.db.put('kv', r, `chat:${r.groupId}`);
  }

  groups(): Group[] {
    if (!this.chat) return [];
    return [...this.chat.groups.values()]
      .filter((g) => !this.records.get(g.id)?.hidden)
      .sort((a, b) => (this.records.get(b.id)?.lastTs ?? 0) - (this.records.get(a.id)?.lastTs ?? 0));
  }

  group(id: string) {
    return this.chat?.groups.get(id);
  }

  isDm(g: Group) {
    try {
      return g.policy.kind === 'dm';
    } catch {
      return false;
    }
  }

  /** The other person in a DM, even before they have joined. */
  dmPeer(g: Group): string | undefined {
    const other = g.members().find((m) => m.address !== this.address);
    if (other) return other.address;
    const inv = this.records.get(g.id)?.invited[0];
    if (inv) return inv;
    const owner = g.space.split('/')[0];
    if (owner && owner !== this.login) return toAddress(owner);
    return undefined;
  }

  title(g: Group): string {
    if (this.isDm(g)) {
      const p = this.dmPeer(g);
      return p ? loginFrom(p) : 'Direct message';
    }
    return g.name || 'Untitled group';
  }

  /** People invited but not yet in the group. */
  pending(g: Group): string[] {
    const inGroup = new Set(g.members().map((m) => m.address));
    return (this.records.get(g.id)?.invited ?? []).filter((a) => !inGroup.has(a));
  }

  async userExists(login: string): Promise<{ login: string } | undefined> {
    const r = await this.ghJson<{ login: string; type: string }>(`/users/${encodeURIComponent(login)}`);
    if (r.status === 404) return undefined;
    if (r.status !== 200) throw new Error(`Could not look up ${login} (${r.status})`);
    return { login: r.data!.login };
  }

  private normLogin(input: string) {
    const l = input.trim().replace(/^@/, '').toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9-]{0,38})$/.test(l)) throw new Error(`"${input}" is not a GitHub username`);
    if (l === this.login) throw new Error('You cannot invite yourself');
    return l;
  }

  async startDm(input: string): Promise<Group> {
    const login = this.normLogin(input);
    const existing = this.groups().find((g) => this.isDm(g) && this.dmPeer(g) === toAddress(login));
    if (existing) return existing;
    if (!(await this.userExists(login))) throw new Error(`No GitHub user named ${login}`);
    const g = await this.chat!.createGroup('dm');
    const r = this.record(g.id);
    r.invited = [toAddress(login)];
    await this.saveRecord(r);
    this.bump();
    await g.invite(toAddress(login));
    await this.systemNote(g.id, `Invitation sent to @${login}. The chat opens for them when they accept in this app.`);
    this.bump();
    return g;
  }

  async createGroup(name: string, inputs: string[]): Promise<{ group: Group; failed: string[] }> {
    const logins = [...new Set(inputs.filter((s) => s.trim()).map((s) => this.normLogin(s)))];
    for (const l of logins) if (!(await this.userExists(l))) throw new Error(`No GitHub user named ${l}`);
    const g = await this.chat!.createGroup('group', name.trim() || undefined);
    this.record(g.id);
    this.bump();
    const failed: string[] = [];
    for (const l of logins) {
      try {
        await this.invite(g, l);
      } catch (e) {
        failed.push(`${l}: ${describeError(e)}`);
      }
    }
    return { group: g, failed };
  }

  async invite(g: Group, input: string) {
    const login = this.normLogin(input);
    if (!(await this.userExists(login))) throw new Error(`No GitHub user named ${login}`);
    await g.invite(toAddress(login));
    const r = this.record(g.id);
    if (!r.invited.includes(toAddress(login))) r.invited.push(toAddress(login));
    await this.saveRecord(r);
    await this.systemNote(g.id, `Invitation sent to @${login}.`);
    this.bump();
  }

  async removeMember(g: Group, fp: string) {
    const who = g.members().find((m) => m.fingerprint === fp);
    await g.remove(fp);
    const r = this.record(g.id);
    if (who) r.invited = r.invited.filter((a) => a !== who.address);
    await this.saveRecord(r);
    await this.syncGroup(g);
  }

  async leave(g: Group) {
    await g.leave();
    const r = this.record(g.id);
    r.hidden = true;
    await this.saveRecord(r);
    if (this.activeGroup === g.id) this.activeGroup = undefined;
    this.bump();
  }

  async hide(g: Group) {
    const r = this.record(g.id);
    r.hidden = true;
    await this.saveRecord(r);
    this.bump();
  }

  async rename(g: Group, name: string) {
    await g.send({ t: 'meta', name });
    await this.syncGroup(g);
  }

  // ---- messages ----

  messages(groupId: string) {
    return this.db.messages<MsgRecord>(groupId);
  }

  async send(g: Group, body: string) {
    const pendingId = Math.random().toString(36).slice(2);
    const list = this.sending.get(g.id) ?? [];
    list.push({ id: pendingId, body, ts: Date.now() });
    this.sending.set(g.id, list);
    this.bump();
    try {
      await g.send({ t: 'text', body });
    } finally {
      this.sending.set(g.id, (this.sending.get(g.id) ?? []).filter((p) => p.id !== pendingId));
      this.bump();
    }
    void this.syncGroup(g);
  }

  async sendFile(g: Group, file: File) {
    if (file.size > 10 * 1024 * 1024) throw new Error('Files up to 10 MB for now.');
    const data = new Uint8Array(await file.arrayBuffer());
    await g.sendAttachment(data, { name: file.name, mime: file.type || undefined });
    void this.syncGroup(g);
  }

  async react(g: Group, ref: string, emoji: string) {
    await g.send({ t: 'react', ref, emoji });
  }

  async deleteMessage(g: Group, ref: string) {
    await g.send({ t: 'delete', ref });
  }

  async fetchFile(g: Group, file: AttachmentRef): Promise<Blob> {
    const data = await g.fetchAttachment(file);
    return new Blob([data as Uint8Array<ArrayBuffer>], { type: file.mime || 'application/octet-stream' });
  }

  private async put(m: MsgRecord) {
    await this.db.put('messages', m);
  }

  private async systemNote(groupId: string, body: string) {
    const ts = Date.now();
    await this.put({ groupId, id: `sys-${ts}-${Math.random().toString(36).slice(2, 8)}`, ts, from: '', fromFp: '', mine: false, kind: 'system', body });
  }

  private async onMessage(g: Group, m: ReceivedMessage) {
    const msg = m.message;
    const mine = m.from.fingerprint === this.identity?.fingerprint;
    const base = { groupId: g.id, id: msg.id, ts: msg.ts, from: m.from.address, fromFp: m.from.fingerprint, mine };
    const r = this.record(g.id);
    const touch = async (preview: string) => {
      r.lastTs = Math.max(r.lastTs, msg.ts);
      r.lastText = preview;
      if (!mine && this.activeGroup !== g.id) r.unread++;
      await this.saveRecord(r);
    };
    switch (msg.t) {
      case 'text':
        await this.put({ ...base, kind: 'text', body: msg.body, reply: msg.reply });
        await touch(msg.body);
        break;
      case 'attachment':
        await this.put({ ...base, kind: 'attachment', file: msg.file, caption: msg.caption });
        await touch(`📎 ${msg.file.name ?? 'file'}`);
        break;
      case 'edit': {
        const cur = await this.db.get<MsgRecord>('messages', [g.id, msg.ref]);
        if (cur && cur.fromFp === m.from.fingerprint) await this.put({ ...cur, body: msg.body, edited: true });
        break;
      }
      case 'delete': {
        const cur = await this.db.get<MsgRecord>('messages', [g.id, msg.ref]);
        if (cur && cur.fromFp === m.from.fingerprint) await this.put({ ...cur, deleted: true, body: undefined, file: undefined, caption: undefined });
        break;
      }
      case 'react': {
        const cur = await this.db.get<MsgRecord>('messages', [g.id, msg.ref]);
        if (cur) {
          const rx = { ...(cur.reactions ?? {}) };
          const who = new Set(rx[msg.emoji] ?? []);
          if (who.has(m.from.address)) who.delete(m.from.address);
          else who.add(m.from.address);
          rx[msg.emoji] = [...who];
          if (!rx[msg.emoji]!.length) delete rx[msg.emoji];
          await this.put({ ...cur, reactions: rx });
        }
        break;
      }
      case 'meta':
        if (msg.name && msg.name !== r.lastName) {
          r.lastName = msg.name;
          await this.saveRecord(r);
          await this.put({ ...base, id: `meta-${msg.id}`, kind: 'system', body: mine ? `You named the group “${msg.name}”` : `@${loginFrom(m.from.address)} named the group “${msg.name}”` });
        }
        break;
      default:
        break;
    }
    this.bump();
  }

  private async onEvents(g: Group, events: GroupEvent[]) {
    // New members (and new devices) can't read anything sent before they joined, so an admin
    // repeats the group name whenever the number of devices in the group goes up.
    const r = this.record(g.id);
    const devices = g.members().reduce((n, m) => n + m.devices.length, 0);
    const shareName = devices > (r.deviceCount ?? 1);
    if (devices !== r.deviceCount) {
      r.deviceCount = devices;
      await this.saveRecord(r);
    }
    for (const e of events) {
      const who = 'address' in e ? `@${loginFrom(e.address)}` : '';
      if (e.type === 'joined') {
        await this.systemNote(g.id, e.address === this.address ? 'You joined. Messages are end-to-end encrypted.' : `${who} joined`);
        this.peers.delete(e.address);
      } else if (e.type === 'left') await this.systemNote(g.id, `${who} left`);
      else if (e.type === 'removed') await this.systemNote(g.id, 'You were removed from this chat.');
      else if (e.type === 'access-lost') await this.systemNote(g.id, 'GitHub no longer gives you access to this chat.');
      else if (e.type === 'undecryptable') await this.systemNote(g.id, 'A message could not be decrypted.');
      else if (e.type === 'rejected') await this.systemNote(g.id, `A change to the group was rejected (${e.reason}).`);
    }
    if (shareName && g.active && !this.isDm(g) && g.name && g.policy.admins.includes(this.identity!.fingerprint)) {
      await g.send({ t: 'meta', name: g.name }).catch(() => undefined);
    }
  }

  async syncGroup(g: Group) {
    try {
      const r = await g.sync();
      await this.onEvents(g, r.events);
      this.groupErrors.delete(g.id);
    } catch (e) {
      this.groupErrors.set(g.id, describeError(e));
    }
    this.bump();
  }

  /** Accept GitHub invitations from the inbox, then join any space with a ticket for us. */
  async checkInvites(force = false) {
    const p = this.provider;
    const chat = this.chat!;
    let notices: Awaited<ReturnType<typeof p.inviteInbox.list>> = [];
    try {
      notices = await p.inviteInbox.list();
    } catch (e) {
      this.lastPollError = describeError(e);
    }
    for (const n of notices) {
      try {
        await p.channel.acceptGrant(n.pointer);
        await p.inviteInbox.delete(n.id);
      } catch (e) {
        this.lastPollError = describeError(e);
      }
    }
    const now = Date.now();
    // Listing every repo the app can see costs a few requests: do it when an invite came in,
    // when asked, or once a minute (covers invites accepted elsewhere and new own devices).
    if (!force && !notices.length && now - this.lastSpaceScan < 60_000) return this.bump();
    this.lastSpaceScan = now;
    const known = new Set([...chat.groups.values()].map((g) => g.space));
    for (const space of await p.channel.listSpaces()) {
      if (known.has(space)) continue;
      const tried = this.joinTried.get(space);
      if (!force && !notices.length && tried && now - tried < JOIN_RETRY_MS) continue;
      try {
        const g = await chat.join(space);
        if (g) {
          this.record(g.id);
          this.joinTried.delete(space);
          await this.syncGroup(g);
        } else this.joinTried.set(space, now);
      } catch (e) {
        this.joinTried.set(space, now);
        this.lastPollError = describeError(e);
      }
    }
    this.bump();
  }

  // ---- polling ----

  setActive(groupId: string | undefined) {
    this.activeGroup = groupId;
    if (groupId) {
      const r = this.records.get(groupId);
      if (r && r.unread) {
        r.unread = 0;
        void this.saveRecord(r);
      }
      this.lastCheck.delete(groupId);
      this.kick?.();
    }
    this.bump();
  }

  /** Has anything been written to this chat's repo since we last looked? 304s are free. */
  private async headChanged(space: string): Promise<boolean> {
    const etag = this.etags.get(space);
    const r = await this.ghFetch(`${CONFIG.api}/repos/${space}/commits?per_page=1`, {
      headers: { Accept: 'application/vnd.github+json', ...(etag ? { 'If-None-Match': etag } : {}) },
    });
    if (r.status === 304) return false;
    if (r.status === 200) {
      const e = r.headers.get('etag');
      if (e) this.etags.set(space, e);
    }
    return true;
  }

  private async loop() {
    while (!this.stopped) {
      try {
        await this.tick();
        this.lastPollError = undefined;
      } catch (e) {
        this.lastPollError = describeError(e);
        this.bump();
      }
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 1500);
        this.kick = () => {
          clearTimeout(t);
          resolve();
        };
      });
    }
  }

  private async tick() {
    if (!this.chat) return;
    const now = Date.now();
    const hidden = document.visibilityState === 'hidden';
    if (now - this.lastInvites > (hidden ? HIDDEN_POLL_MS : INVITE_POLL_MS)) {
      this.lastInvites = now;
      await this.checkInvites();
    }
    for (const g of this.chat.groups.values()) {
      if (!g.active) continue;
      const rec = this.records.get(g.id);
      // Recently busy chats, and chats waiting for someone to join, are checked more often.
      const warm = rec && (now - rec.lastTs < 2 * 60_000 || this.pending(g).length > 0);
      const every = hidden ? HIDDEN_POLL_MS : g.id === this.activeGroup ? ACTIVE_POLL_MS : warm ? WARM_POLL_MS : IDLE_POLL_MS;
      if (now - (this.lastCheck.get(g.id) ?? 0) < every) continue;
      this.lastCheck.set(g.id, Date.now());
      try {
        if (await this.headChanged(g.space)) await this.syncGroup(g);
      } catch (e) {
        this.groupErrors.set(g.id, describeError(e));
      }
    }
  }

  stop() {
    this.stopped = true;
    this.kick?.();
  }

  // ---- people ----

  peer(address: string, refresh = false): Promise<PeerInfo> {
    if (refresh) this.peers.delete(address);
    let p = this.peers.get(address);
    if (!p) {
      p = this.lookupPeer(address);
      this.peers.set(address, p);
    }
    return p;
  }

  private async lookupPeer(address: string): Promise<PeerInfo> {
    try {
      const r = await this.registry.lookup(address);
      if (r.status === 'none') return { address, status: 'none' };
      const fp = r.view.fingerprint;
      const pin = await this.registry.pins.get(address);
      return {
        address,
        status: r.status,
        fingerprint: fp,
        safety: await safetyNumber(this.identity!.fingerprint, fp),
        verified: r.status === 'ok' && !!pin?.verified,
      };
    } catch (e) {
      return { address, status: 'error', error: describeError(e) };
    }
  }

  async markVerified(address: string) {
    await this.registry.markVerified(address);
    this.peers.delete(address);
    this.bump();
  }

  async acceptKeyChange(address: string) {
    const r = await this.registry.lookup(address);
    if (r.status === 'key-changed') await this.registry.acceptKeyChange(address, r.view);
    this.peers.delete(address);
    this.bump();
  }

  async myFingerprint() {
    return this.identity?.fingerprint;
  }
}

export { sleep };
