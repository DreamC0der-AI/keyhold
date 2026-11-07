import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Group } from '@keyhold/chat/index';
import type { AttachmentRef } from '@keyhold/chat/messages';
import { describeError, loginFrom, type MsgRecord, type PeerInfo, type Session } from '../lib/session';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, useAction } from '../ui';

const clock = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const msgTime = (ts: number) => (timeLabel(ts) === clock(ts) ? clock(ts) : `${timeLabel(ts)} ${clock(ts)}`);
const EMOJI = ['👍', '❤️', '😂', '🎉', '👀'];

export function Conversation({ session, group }: { session: Session; group: Group }) {
  const [msgs, setMsgs] = useState<MsgRecord[]>([]);
  const [panel, setPanel] = useState(false);
  const [verify, setVerify] = useState<string>();
  const [peer, setPeer] = useState<PeerInfo>();
  const v = session.getVersion();
  const dm = session.isDm(group);
  const peerAddr = dm ? session.dmPeer(group) : undefined;
  const title = session.title(group);
  const listRef = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);

  useEffect(() => {
    let live = true;
    void session.messages(group.id).then((m) => live && setMsgs(m));
    return () => {
      live = false;
    };
  }, [v, group.id]);

  useEffect(() => {
    if (!peerAddr) return;
    let live = true;
    void session.peer(peerAddr).then((p) => live && setPeer(p));
    return () => {
      live = false;
    };
  }, [peerAddr, v]);

  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [msgs.length, session.sending.get(group.id)?.length]);

  const pending = session.pending(group);
  const sending = session.sending.get(group.id) ?? [];
  const err = session.groupErrors.get(group.id);
  const joined = group.members().length > 1;

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
              {!dm && <> · {group.members().length} {group.members().length === 1 ? 'member' : 'members'}</>}
              <span className="hide-sm"> · <span className="mono">{group.space.split('/')[1]}</span></span>
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
      <div className="convo-body">
        <div
          className="messages"
          ref={listRef}
          onScroll={(e) => {
            const el = e.currentTarget;
            atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
          }}
        >
          {msgs.map((m) => <Message key={m.id} m={m} session={session} group={group} showAuthor={!dm} />)}
          {sending.map((p) => (
            <div key={p.id} className="msg mine">
              <div className="col">
                <div className="bubble pending">{p.body}</div>
                <span className="msg-meta"><span className="spinner" style={{ width: 10, height: 10 }} /> Encrypting and sending…</span>
              </div>
            </div>
          ))}
          {!joined && pending.length > 0 && (
            <div className="sys">Waiting for {pending.map((a) => '@' + loginFrom(a)).join(', ')} to accept. You can send messages once someone has joined.</div>
          )}
        </div>
        {panel && (
          <Details session={session} group={group} onClose={() => setPanel(false)} onVerify={setVerify} />
        )}
      </div>
      <Composer session={session} group={group} disabledReason={!group.active ? 'You are no longer a member of this chat.' : !joined ? 'Waiting for the other person to join…' : undefined} error={err} />
      {verify && <VerifyModal session={session} address={verify} onClose={() => setVerify(undefined)} />}
    </>
  );
}

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

function Message({ m, session, group, showAuthor }: { m: MsgRecord; session: Session; group: Group; showAuthor: boolean }) {
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
          {m.deleted ? 'Message deleted' : m.kind === 'attachment' && m.file ? <FileView session={session} group={group} file={m.file} caption={m.caption} /> : m.body}
        </div>
        {reactions.length > 0 && (
          <div className="reactions">
            {reactions.map(([e, who]) => (
              <button key={e} className={`reaction${who.includes(session.address) ? ' me' : ''}`} title={who.map(loginFrom).join(', ')} onClick={() => act(() => session.react(group, m.id, e))}>
                {e} {who.length}
              </button>
            ))}
          </div>
        )}
        <span className="msg-meta">
          {msgTime(m.ts)}
          {m.edited && ' · edited'}
          {!m.deleted && group.active && (
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

function Details({ session, group, onClose, onVerify }: { session: Session; group: Group; onClose: () => void; onVerify: (a: string) => void }) {
  const dm = session.isDm(group);
  const members = group.members();
  const policy = group.policy;
  const iAmAdmin = policy.admins.includes(session.identity!.fingerprint);
  const pending = session.pending(group);
  const [invite, setInvite] = useState('');
  const [name, setName] = useState(group.name ?? '');
  const { busy, error, run } = useAction();
  return (
    <aside className="panel" aria-label="Chat details">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h3>{dm ? 'Details' : 'Members'}</h3>
        <button className="btn icon" onClick={onClose} aria-label="Close panel">{Icon.close()}</button>
      </div>
      <ErrorFlash error={error} />
      {!dm && iAmAdmin && group.active && (
        <form className="stack" style={{ gap: 6 }} onSubmit={(e) => { e.preventDefault(); void run(() => session.rename(group, name.trim())); }}>
          <label className="field">Group name<input className="input" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <button className="btn" disabled={busy || !name.trim() || name.trim() === group.name}>Rename</button>
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
              {!me && !dm && iAmAdmin && group.active && (
                <button className="btn danger" disabled={busy} onClick={() => confirm(`Remove ${login} from the group? Keys rotate right away.`) && run(() => session.removeMember(group, m.fingerprint))}>Remove</button>
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
      {!dm && iAmAdmin && group.active && (
        <form className="stack" style={{ gap: 6 }} onSubmit={(e) => { e.preventDefault(); void run(async () => { await session.invite(group, invite); setInvite(''); }); }}>
          <label className="field">Invite someone<input className="input" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="GitHub username" autoComplete="off" /></label>
          <button className="btn primary" disabled={busy || !invite.trim()}>{busy ? <span className="spinner" /> : 'Invite'}</button>
        </form>
      )}
      <div className="stack small muted" style={{ gap: 6 }}>
        <span>Stored in <a href={`https://github.com/${group.space}`} target="_blank" rel="noreferrer" className="mono">{group.space}</a>. The files there are ciphertext.</span>
        <span>Key epoch {String(group.epoch)}. Keys rotate every 7 days or 100 messages, and whenever someone leaves.</span>
      </div>
      {group.active ? (
        <button className="btn danger" disabled={busy} onClick={() => confirm(dm ? 'Leave this chat? You will not be able to read it any more.' : 'Leave this group?') && run(async () => { await session.leave(group); go('/'); })}>
          Leave {dm ? 'chat' : 'group'}
        </button>
      ) : (
        <button className="btn" onClick={() => run(async () => { await session.hide(group); go('/'); })}>Remove from list</button>
      )}
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
