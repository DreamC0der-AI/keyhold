import { describe, it, expect } from 'vitest';
import { MemoryWorld } from '../src/storage/index.js';
import { makeUser, texts } from './chat-helpers.js';

describe('offline add, then many epochs before the invitee comes online', () => {
  it('invitee added with a reusable pre-key reads everything after many epochs, joins and leaves', async () => {
    let t = Date.UTC(2026, 10, 20);
    const now = () => t;
    const w = new MemoryWorld();
    const opts = { build: { offlineAdd: true, lastResortKeyPackages: true }, now, rotation: { maxMessages: 100, maxAgeMs: 7 * 86_400_000 } };
    const bob = await makeUser(w.session('mem:bob'), 'mem:bob', opts);
    const dave = await makeUser(w.session('mem:dave'), 'mem:dave', opts);
    const erin = await makeUser(w.session('mem:erin'), 'mem:erin', opts);
    const carol = await makeUser(w.session('mem:carol'), 'mem:carol', opts);
    await carol.writer.setLastResortKeyPackage(carol.root, await carol.chat.lastResortKeyPackage());

    const g = await bob.chat.createGroup('group', 'stress');
    const g2 = await bob.chat.createGroup('group', 'second');
    await g.invite(dave.address);
    const [gd] = await dave.chat.acceptInvites();
    await g.sync();
    await g.addOffline(carol.address);
    await g2.addOffline(carol.address); // same reusable key, second group
    const sent: string[] = [];
    const epoch0 = g.epoch;
    for (let i = 0; i < 260; i++) {
      const who = i % 3 === 0 && i <= 200 ? gd! : g;
      await who.send({ t: 'text', body: `m${i}` });
      sent.push(`m${i}`);
      if (i % 3 === 0 || i > 200) await g.sync(); else await gd!.sync();
      if (i === 50) { t += 8 * 86_400_000; } // time-based rotation
      if (i === 120) { await g.invite(erin.address); const [ge] = await erin.chat.acceptInvites(); await g.sync(); await gd!.sync(); await ge!.send({ t: 'text', body: 'erin here' }); sent.push('erin here'); await g.sync(); await gd!.sync(); await ge!.leave(); await g.sync(); await gd!.sync(); }
      if (i === 200) { await gd!.leave(); await g.sync(); }
    }
    await g2.send({ t: 'text', body: 'second group' });
    const epochs = Number(g.epoch - epoch0);
    const joined = await carol.chat.acceptInvites();
    expect(joined.length).toBe(2);
    const gc = joined.find((x) => x.id === g.id)!;
    expect(epochs).toBeGreaterThanOrEqual(5);
    expect(texts(await gc.sync())).toEqual(sent);
    const gc2 = joined.find((x) => x.id === g2.id)!;
    expect(texts(await gc2.sync())).toEqual(['second group']);
  }, 120_000);
});
