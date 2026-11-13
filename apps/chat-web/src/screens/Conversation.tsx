import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Group } from '@keyhold/chat/index';
import type { AttachmentRef } from '@keyhold/chat/messages';
import { describeError, loginFrom, type Convo, type MsgRecord, type PeerInfo, type Session } from '../lib/session';
import { endedText } from './Home';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, useAction } from '../ui';

const clock = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const msgTime = (ts: number) => (timeLabel(ts) === clock(ts) ? clock(ts) : `${timeLabel(ts)} ${clock(ts)}`);
const EMOJI = ['👍', '❤️', '😂', '🎉', '👀'];

type Item = { kind: 'msg'; m: MsgRecord; group?: Group } | { kind: 'divider'; id: string; text: string };

export function Conversation({ session, convo }: { session: Session; convo: Convo }) {
  const [items, setItems] = useState<Item[]>([]);
  const [panel, setPanel] = useState(false);
  const [verify, setVerify] = useState<string>();
  const [peer, setPeer] = useState<PeerInfo>();
  const v = session.getVersion();
  const dm = convo.dm;
  const live = convo.live;
  const group = live ?? convo.current;
  const peerAddr = convo.peer;
  const title = convo.title;
  const listRef = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);
  const roomIds = convo.rooms.map((r) => r.groupId).join(',');
  const { busy, error, run } = useAction();

  useEffect(() => {
    let alive = true;
    void Promise.all(convo.rooms.map((r) => session.messages(r.groupId))).then((lists) => {
      if (!alive) return;
      const out: Item[] = [];
      convo.rooms.forEach((r, i) => {
        const g = session.group(r.groupId);
        for (const m of lists[i]!) out.push({ kind: 'msg', m, group: g });
        const later = i < convo.rooms.length - 1;
        if (r.ended) {
          const when = new Date(r.ended.at).toLocaleDateString([], { day: 'numeric', month: 'short' });
          out.push({ kind: 'divider', id: `end-${r.groupId}`, text: `${endedText(session, r.ended, dm)} on ${when}${later ? ' · new chat started' : ''}` });
        } else if (later) out.push({ kind: 'divider', id: `end-${r.groupId}`, text: 'New chat started' });
      });
      setItems(out);
    });
    return () => {
      alive = false;
    };
  }, [v, roomIds]);

  useEffect(() => {
    if (!peerAddr) return;
    let alive = true;
    void session.peer(peerAddr).then((p) => alive && setPeer(p));
    return () => {
      alive = false;
    };
  }, [peerAddr, v]);

  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [items.length, live && session.sending.get(live.id)?.length]);

  const liveRec = live ? session.records.get(live.id) : undefined;
  const pending = live ? session.pending(live) : [];
  const sending = live ? session.sending.get(live.id) ?? [] : [];
  const err = group ? session.groupErrors.get(group.id) : undefined;
  const joined = !!live && live.members().length > 1;
  const peerLeft = !!live && dm && !!liveRec?.peerLeft && !joined;
  const last = convo.rooms[convo.rooms.length - 1]!;
  const space = group?.space ?? last.space;
  const startNew = () => run(async () => go(`/c/${encodeURIComponent(await session.startDm(loginFrom(peerAddr!)))}`));

  return (
    <>
      <div className="convo-head">
        <div className="who">
          <a href="#/" className="btn icon mobile-only" aria-label="Back to chats">{Icon.back()}</a>
          <Avatar name={title} login={peerAddr ? loginFrom(peerAddr) : undefined} square={!dm} size="lg" />
          <div style={{ minWidth: 0 }}>
            <strong style={{ fontSize: 16 }}>{title}</strong>
            <div className="small muted row" style={{ gap: 4 }}>
              {Icon.lock()} End-to-end encrypted
              {!dm && group && <> · {group.members().length} {group.members().length === 1 ? 'member' : 'members'}</>}
              {space && <span className="hide-sm"> · <span className="mono">{space.split('/')[1]}</span></span>}
            </div>
          </div>
        </div>
        <div className="row">
          {dm && peer && <TrustBadge peer={peer} onClick={() => setVerify(peer.address)} />}
          <button className="btn" onClick={() => setPanel((p) => !p)} aria-expanded={panel}>
            {Icon.people()} <span className="hide-sm">{dm ? 'Details' : 'Members'}</span>
          </button>
        </div>
      </div>
      {peer?.status === 'key-changed' && (
        <div className="flash warn" style={{ margin: '8px 16px 0', borderRadius: 6 }}>
          <strong>{loginFrom(peer.address)}'s identity key changed.</strong> They may have a new device or reset their account, or someone may be impersonating them. <button className="btn link" onClick={() => setVerify(peer.address)}>Review</button>
        </div>
      )}
      {peerLeft && (
        <div className="flash warn banner" style={{ margin: '8px 16px 0', borderRadius: 6 }}>
          <strong>{title} left this chat.</strong> You can't send messages here any more.{' '}
          {session.isOwner(live!) && <button className="btn danger" disabled={busy} onClick={() => confirm(CLOSE_CONFIRM) && run(() => session.closeChat(live!))}>Close chat</button>}
        </div>
      )}
      {!live && (
        <div className="flash banner" style={{ margin: '8px 16px 0', borderRadius: 6 }}>
          <strong>{group ? 'This chat is no longer available.' : `${last.ended ? endedText(session, last.ended, dm) : 'This chat has ended'}.`}</strong>{' '}
          {group ? "GitHub doesn't let you open it right now. If access comes back, it carries on. " : 'Your copy of the messages stays here until you delete it. '}
          <span className="row" style={{ marginTop: 6 }}>
            {dm && peerAddr && !session.blocked.has(peerAddr) && <button className="btn primary" disabled={busy} onClick={startNew}>Start a new chat with {title}</button>}
            <button className="btn" disabled={busy} onClick={() => confirm(DELETE_CONFIRM(dm ? title : undefined)) && run(async () => { await session.deleteHistory(convo.key); go('/'); })}>Delete chat</button>
          </span>
        </div>
      )}
      <ErrorFlash error={error} />
      <div className="convo-body">
        <div
          className="messages"
          ref={listRef}
          onScroll={(e) => {
            const el = e.currentTarget;
            atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
          }}
        >
          {items.map((it) => it.kind === 'divider'
            ? <div key={it.id} className="sys divider">{it.text}</div>
            : <Message key={`${it.m.groupId}/${it.m.id}`} m={it.m} session={session} group={it.group} showAuthor={!dm} />)}
          {sending.map((p) => (
            <div key={p.id} className="msg mine">
              <div className="col">
                <div className="bubble pending">{p.body}</div>
                <span className="msg-meta"><span className="spinner" style={{ width: 10, height: 10 }} /> Encrypting and sending…</span>
              </div>
            </div>
          ))}
          {live && !joined && !peerLeft && pending.length > 0 && (
            <div className="sys">Waiting for {pending.map((a) => '@' + loginFrom(a)).join(', ')} to accept. You can send messages once someone has joined.</div>
          )}
        </div>
        {panel && (
          <Details session={session} convo={convo} group={group} onClose={() => setPanel(false)} onVerify={setVerify} />
        )}
      </div>
      {live ? (
        <Composer session={session} group={live} disabledReason={peerLeft ? `${title} left this chat` : !joined ? 'Waiting for the other person to join…' : undefined} error={err} />
      ) : (
        <div className="composer"><div className="composer-foot"><span>This chat has ended. Nothing can be sent here.</span></div></div>
      )}
      {verify && <VerifyModal session={session} address={verify} onClose={() => setVerify(undefined)} />}
    </>
  );
}

const CLOSE_CONFIRM = 'Close this chat? It ends for everyone and its repo is deleted from GitHub. Everyone keeps the messages their app has, unless they delete them.';
const QUIT_CONFIRM = 'Quit this chat? You stop receiving messages. Your copy of the history stays here until you delete it.';
const DELETE_CONFIRM = (peer?: string) => `Delete this chat's messages from this browser? ${peer ?? 'The other members'} keep${peer ? 's' : ''} their copy.`;

function TrustBadge({ peer, onClick }: { peer: PeerInfo; onClick: () => void }) {
  if (peer.status === 'none') return <span className="label">No identity yet</span>;
  if (peer.status === 'error') return null;
  if (peer.status === 'key-changed') return <button className="label yellow" style={{ cursor: 'pointer', background: 'none' }} onClick={onClick}>{Icon.shield(false)} Key changed</button>;
  return peer.verified ? (
    <button className="label green" style={{ cursor: 'pointer', background: 'none' }} onClick={onClick}>{Icon.shield(true)} Verified</button>
  ) : (
    <button className="label yellow" style={{ cursor: 'pointer', background: 'none' }} onClick={onClick}>{Icon.shield(false)} Unverified · compare</button>
  );
}

function Message({ m, session, group, showAuthor }: { m: MsgRecord; session: Session; group?: Group; showAuthor: boolean }) {
  if (m.kind === 'system') return <div className="sys">{m.body}</div>;
  const who = loginFrom(m.from);
  const reactions = Object.entries(m.reactions ?? {});
  const act = (fn: () => Promise<unknown>) => fn().catch((e) => alert(describeError(e)));
  return (
    <div className={`msg${m.mine ? ' mine' : ''}`}>
      {!m.mine && <Avatar name={who} login={who} size="sm" />}
      <div className="col">
        {showAuthor && !m.mine && <span className="small muted">{who}</span>}
        <div className={`bubble${m.deleted ? ' deleted' : ''}`}>
          {m.deleted ? 'Message deleted' : m.kind === 'attachment' && m.file ? (group ? <FileView session={session} group={group} file={m.file} caption={m.caption} /> : <span className="muted">📎 {m.file.name ?? 'file'} (no longer available)</span>) : m.body}
        </div>
        {reactions.length > 0 && (
          <div className="reactions">
            {reactions.map(([e, who]) => (
              <button key={e} className={`reaction${who.includes(session.address) ? ' me' : ''}`} title={who.map(loginFrom).join(', ')} disabled={!group?.active} onClick={() => group && act(() => session.react(group, m.id, e))}>
                {e} {who.length}
              </button>
            ))}
          </div>
        )}
        <span className="msg-meta">
          {msgTime(m.ts)}
          {m.edited && ' · edited'}
          {!m.deleted && group?.active && (
            <span className="msg-actions">
              {EMOJI.map((e) => (
                <button key={e} onClick={() => act(() => session.react(group, m.id, e))} aria-label={`React ${e}`}>{e}</button>
              ))}
              {m.mine && <button onClick={() => confirm('Delete this message for everyone?') && act(() => session.deleteMessage(group, m.id))}>Delete</button>}
            </span>
          )}
        </span>
      </div>
    </div>
  );
}

function FileView({ session, group, file, caption }: { session: Session; group: Group; file: AttachmentRef; caption?: string }) {
  const [url, setUrl] = useState<string>();
  const { busy, error, run } = useAction();
  const isImage = file.mime?.startsWith('image/');
  useEffect(() => () => { if (url) URL.revokeObjectURL(url); }, [url]);
  const load = () => run(async () => {
    const blob = await session.fetchFile(group, file);
    const u = URL.createObjectURL(blob);
    setUrl(u);
    return u;
  });
  const size = file.size > 1024 * 1024 ? `${(file.size / 1024 / 1024).toFixed(1)} MB` : `${Math.ceil(file.size / 1024)} KB`;
  return (
    <div className="stack" style={{ gap: 6 }}>
      {isImage && url ? (
        <a href={url} download={file.name} target="_blank" rel="noreferrer"><img src={url} alt={file.name ?? 'image'} style={{ maxWidth: 280, maxHeight: 280, borderRadius: 6, display: 'block' }} /></a>
      ) : (
        <div className="file">
          {Icon.clip()}
          <span>{file.name ?? 'file'} <span className="muted small">{size}</span></span>
          {url ? (
            <a className="btn" href={url} download={file.name ?? 'file'}>Save</a>
          ) : (
            <button className="btn" disabled={busy} onClick={() => load()}>{busy ? <span className="spinner" /> : isImage ? 'Show' : 'Download'}</button>
          )}
        </div>
      )}
      {caption && <span>{caption}</span>}
      {error && <span className="small" style={{ color: 'var(--danger)' }}>{error}</span>}
    </div>
  );
}

function Composer({ session, group, disabledReason, error }: { session: Session; group: Group; disabledReason?: string; error?: string }) {
  const draftKey = `kh.draft.${group.id}`;
  const [text, setText] = useState(() => sessionStorage.getItem(draftKey) ?? '');
  const { busy, error: sendError, run } = useAction();
  const fileRef = useRef<HTMLInputElement>(null);
  const taRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    sessionStorage.setItem(draftKey, text);
    const ta = taRef.current;
    if (ta) {
      ta.style.height = 'auto';
      ta.style.height = `${Math.min(ta.scrollHeight, 160)}px`;
    }
  }, [text]);
  const send = () => {
    const body = text.trim();
    if (!body || disabledReason) return;
    setText('');
    void run(async () => {
      try {
        await session.send(group, body);
      } catch (e) {
        setText(body);
        throw e;
      }
    });
  };
  return (
    <div className="composer">
      {(sendError || error) && <ErrorFlash error={sendError ?? `Sync problem: ${error}`} />}
      <div className="composer-row">
        <button className="btn icon" style={{ border: 0, background: 'none' }} aria-label="Attach file" disabled={!!disabledReason || busy} onClick={() => fileRef.current?.click()}>{Icon.clip()}</button>
        <input ref={fileRef} type="file" hidden onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (f) void run(() => session.sendFile(group, f));
        }} />
        <label htmlFor="composer" className="sr">Message</label>
        <textarea
          id="composer"
          ref={taRef}
          rows={1}
          value={text}
          placeholder={disabledReason ?? `Message ${session.title(group)}`}
          disabled={!!disabledReason}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
              e.preventDefault();
              send();
            }
          }}
        />
        <button className="btn primary" onClick={send} disabled={!!disabledReason || !text.trim()}>Send</button>
      </div>
      <div className="composer-foot">
        <span>Encrypted in this browser before it's saved to GitHub</span>
        <span className="hide-sm">Enter to send · Shift+Enter for a new line</span>
      </div>
    </div>
  );
}

function Details({ session, convo, group, onClose, onVerify }: { session: Session; convo: Convo; group?: Group; onClose: () => void; onVerify: (a: string) => void }) {
  const dm = convo.dm;
  const members = group?.members() ?? [];
  const iAmAdmin = !!group && group.policy.admins.includes(session.identity!.fingerprint);
  const live = convo.live;
  const pending = live ? session.pending(live) : [];
  const [invite, setInvite] = useState('');
  const [name, setName] = useState(group?.name ?? '');
  const { busy, error, run } = useAction();
  const peer = convo.peer;
  const blocked = !!peer && session.blocked.has(peer);
  const owner = !!live && session.isOwner(live);
  return (
    <aside className="panel" aria-label="Chat details">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h3>{dm ? 'Details' : 'Members'}</h3>
        <button className="btn icon" onClick={onClose} aria-label="Close panel">{Icon.close()}</button>
      </div>
      <ErrorFlash error={error} />
      {!dm && iAmAdmin && live && (
        <form className="stack" style={{ gap: 6 }} onSubmit={(e) => { e.preventDefault(); void run(() => session.rename(live, name.trim())); }}>
          <label className="field">Group name<input className="input" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <button className="btn" disabled={busy || !name.trim() || name.trim() === live.name}>Rename</button>
        </form>
      )}
      <div>
        {members.map((m) => {
          const login = loginFrom(m.address);
          const me = m.address === session.address;
          return (
            <div className="member" key={m.fingerprint}>
              <Avatar name={login} login={login} size="sm" />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="row" style={{ gap: 4 }}>
                  <strong>{login}</strong>{me && <span className="muted">(you)</span>}
                  {m.admin && !dm && <span className="label blue">Admin</span>}
                </div>
                <div className="small muted">{m.devices.length} {m.devices.length === 1 ? 'device' : 'devices'}</div>
              </div>
              {!me && <button className="btn link small" onClick={() => onVerify(m.address)}>Verify</button>}
              {!me && !dm && iAmAdmin && live && (
                <button className="btn danger" disabled={busy} onClick={() => confirm(`Remove ${login} from the group? Keys rotate right away.`) && run(() => session.removeMember(live, m.fingerprint))}>Remove</button>
              )}
            </div>
          );
        })}
        {pending.map((a) => (
          <div className="member" key={a}>
            <Avatar name={loginFrom(a)} login={loginFrom(a)} size="sm" />
            <div style={{ flex: 1 }}><strong>{loginFrom(a)}</strong><div className="small muted">Invited, not joined yet</div></div>
          </div>
        ))}
      </div>
      {!dm && iAmAdmin && live && (
        <form className="stack" style={{ gap: 6 }} onSubmit={(e) => { e.preventDefault(); void run(async () => { await session.invite(live, invite); setInvite(''); }); }}>
          <label className="field">Invite someone<input className="input" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="GitHub username" autoComplete="off" /></label>
          <button className="btn primary" disabled={busy || !invite.trim()}>{busy ? <span className="spinner" /> : 'Invite'}</button>
        </form>
      )}
      {group && (
        <div className="stack small muted" style={{ gap: 6 }}>
          <span>Stored in <a href={`https://github.com/${group.space}`} target="_blank" rel="noreferrer" className="mono">{group.space}</a>. The files there are ciphertext.</span>
          <span>Key epoch {String(group.epoch)}. Keys rotate every 7 days or 100 messages, and whenever someone leaves.</span>
        </div>
      )}
      <div className="stack" style={{ gap: 6 }}>
        {live && owner && (
          <>
            <button className="btn danger" disabled={busy} onClick={() => confirm(CLOSE_CONFIRM) && run(() => session.closeChat(live))}>Close chat</button>
            <span className="small muted">Ends it for everyone and deletes its repo. You started it, so only you can close it.</span>
          </>
        )}
        {live && !owner && (
          <>
            <button className="btn danger" disabled={busy} onClick={() => confirm(QUIT_CONFIRM) && run(() => session.quitChat(live))}>Quit chat</button>
            <span className="small muted">You leave; {dm ? `${convo.title} keeps` : 'the others keep'} the chat.</span>
          </>
        )}
        <button className="btn" disabled={busy} onClick={() => confirm(DELETE_CONFIRM(dm ? convo.title : undefined)) && run(async () => { await session.deleteHistory(convo.key); if (!live) go('/'); })}>Delete chat</button>
        <span className="small muted">Deletes the messages in this browser only.{live ? ' The chat stays open.' : ''}</span>
        {dm && peer && (blocked ? (
          <button className="btn" disabled={busy} onClick={() => run(() => session.unblock(peer))}>Unblock {convo.title}</button>
        ) : (
          <button className="btn danger" disabled={busy} onClick={() => confirm(`Block ${convo.title}? ${live ? (owner ? 'This chat is closed, and ' : 'You quit this chat, and ') : ''}their invitations are turned down without asking you.`) && run(() => session.block(peer))}>Block {convo.title}</button>
        ))}
      </div>
    </aside>
  );
}

function VerifyModal({ session, address, onClose }: { session: Session; address: string; onClose: () => void }) {
  const [p, setP] = useState<PeerInfo>();
  const { busy, error, run } = useAction();
  const login = loginFrom(address);
  const v = session.getVersion();
  useEffect(() => {
    void session.peer(address, true).then(setP);
  }, [address, v]);
  return (
    <Modal title={`Verify ${login}`} onClose={onClose}>
      {!p ? <span className="spinner" /> : p.status === 'none' ? (
        <p>{login} hasn't created an identity yet.</p>
      ) : p.status === 'error' ? (
        <ErrorFlash error={p.error} />
      ) : (
        <>
          {p.status === 'key-changed' && (
            <div className="flash warn">{login}'s identity key is different from the one you saw before. Compare the new safety number with them in person or on a call before you accept it.</div>
          )}
          <p>Compare these numbers with {login} in person or on a call. If they match on both screens, nobody is in the middle.</p>
          <div className="safety">{p.safety?.split(' ').map((g, i) => <span key={i}>{g}</span>)}</div>
          <p className="small muted">Their key fingerprint: <span className="mono">{p.fingerprint?.slice(0, 32)}…</span></p>
          <ErrorFlash error={error} />
          {p.status === 'key-changed' ? (
            <button className="btn primary block" disabled={busy} onClick={() => run(() => session.acceptKeyChange(address))}>Numbers match, accept the new key</button>
          ) : p.verified ? (
            <div className="flash">{Icon.shield(true)} You marked {login} as verified.</div>
          ) : (
            <button className="btn primary block" disabled={busy} onClick={() => run(() => session.markVerified(address))}>Numbers match, mark as verified</button>
          )}
        </>
      )}
    </Modal>
  );
}
