import { MemoryWorld, memoryDevice, resolveFeatures, type BuildOptions, type StorageProvider } from '../src/storage/index.js';
import { Chat, createDeviceIdentity, createRootKey, DirectoryWriter, IdentityRegistry, MemoryPinStore, newDeviceId, type RotationPolicy } from '../src/chat/index.js';

export interface TestUserOptions {
  build?: BuildOptions;
  rotation?: RotationPolicy;
  now?: () => number;
  retainEpochs?: number;
}

/** A person with one device: root key, published directory, chat client. */
export async function makeUser(provider: StorageProvider, address: string, o: TestUserOptions = {}) {
  const root = createRootKey();
  const device = memoryDevice(o.now);
  const identity = await createDeviceIdentity(device, root, address, newDeviceId(), o.now?.());
  const writer = new DirectoryWriter(provider.directory, address, o.now);
  await writer.publish(root, identity.cert, { name: address });
  const registry = new IdentityRegistry(provider.directory, new MemoryPinStore(), o.now);
  const features = resolveFeatures(provider, o.build);
  const chat = await Chat.open({ provider, device, identity, registry, features, rotation: o.rotation, now: o.now, retainEpochs: o.retainEpochs });
  return { address, root, device, identity, writer, registry, provider, chat, features };
}

export type TestUser = Awaited<ReturnType<typeof makeUser>>;

/** Another device for an existing person, certified by their root. */
export async function addDevice(u: TestUser, o: TestUserOptions = {}) {
  const device = memoryDevice(o.now);
  const identity = await createDeviceIdentity(device, u.root, u.address, newDeviceId(), o.now?.());
  await u.writer.addDevice(u.root, identity.cert);
  const registry = new IdentityRegistry(u.provider.directory, new MemoryPinStore(), o.now);
  const chat = await Chat.open({ provider: u.provider, device, identity, registry, features: u.features, rotation: o.rotation, now: o.now });
  return { ...u, device, identity, registry, chat };
}

export function world(opts?: ConstructorParameters<typeof MemoryWorld>[0]) {
  return new MemoryWorld(opts);
}

export const texts = (r: { messages: { message: { t: string; body?: string } }[] }) =>
  r.messages.filter((m) => m.message.t === 'text').map((m) => (m.message as { body: string }).body);

import { MockGitHub } from './github-mock.js';
import { githubProvider, toAddress } from '../src/providers/github/index.js';

/** A GitHub "world": one mock GitHub, and a provider session per user. */
export function githubWorld() {
  const gh = new MockGitHub();
  return {
    gh,
    session(login: string) {
      const u = gh.users.get(login) ?? gh.addUser(login);
      return githubProvider({ fetch: gh.fetch, token: u.token, login, workerUrl: gh.worker, apiBase: gh.api });
    },
    address: toAddress,
  };
}
