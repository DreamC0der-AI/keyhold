import { Fragment, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Group } from '@keyhold/chat/index';
import type { AttachmentRef } from '@keyhold/chat/messages';
import { describeError, loginFrom, type Convo, type MsgRecord, type PeerInfo, type Session } from '../lib/session';
import { endedText } from './Home';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, Tip, useAction } from '../ui';

const clock = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
const msgTime = (ts: number) => (timeLabel(ts) === clock(ts) ? clock(ts) : `${timeLabel(ts)} ${clock(ts)}`);
const EMOJI = ['👍', '❤️', '😂', '🎉', '👀'];
const RUN_GAP = 5 * 60_000;
const dayKey = (ts: number) => new Date(ts).toDateString();
function dayLabel(ts: number) {
  const now = new Date();
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  const k = dayKey(ts);
  if (k === now.toDateString()) return 'Today';
  if (k === y.toDateString()) return 'Yesterday';
  const d = new Date(ts);
  return d.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', ...(d.getFullYear() === now.getFullYear() ? {} : { year: 'numeric' }) });
}
/** Two messages read as one run: same sender, a few minutes apart, same day. */
function sameRun(a: Item | undefined, b: Item | undefined) {
  if (a?.kind !== 'msg' || b?.kind !== 'msg') return false;
  if (a.m.kind === 'system' || b.m.kind === 'system') return false;
  return a.m.from === b.m.from && a.m.mine === b.m.mine && Math.abs(b.m.ts - a.m.ts) < RUN_GAP && dayKey(a.m.ts) === dayKey(b.m.ts);
}

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
        <a href="#/" className="btn icon ghost mobile-only" aria-label="Back to chats">{Icon.back()}</a>
        <button className="who" onClick={() => setPanel(true)} aria-label={`About ${title}`}>
          <Avatar name={title} login={peerAddr ? loginFrom(peerAddr) : undefined} square={!dm} size="lg" />
          <span className="who-text">
            <strong className="convo-title">{title}</strong>
            <span className="convo-sub">
              {Icon.lock()}
              {dm ? (peerAddr ? `@${loginFrom(peerAddr)}` : 'Encrypted') : group ? `${group.members().length} ${group.members().length === 1 ? 'member' : 'members'}` : 'Encrypted'}
            </span>
          </span>
        </button>
        <div className="convo-actions">
          {dm && peer && <TrustBadge peer={peer} onClick={() => setVerify(peer.address)} />}
          <button className={`btn icon ghost${panel ? ' on' : ''}`} onClick={() => setPanel((p) => !p)} aria-expanded={panel} aria-haspopup="dialog" data-menu-toggle aria-label="Chat options" title="Chat options">
            {Icon.dots()}
          </button>
        </div>
        {panel && (
          <ChatMenu session={session} convo={convo} group={group} peer={peer} onClose={() => setPanel(false)} onVerify={(a) => { setPanel(false); setVerify(a); }} />
        )}
      </div>
      {peer?.status === 'key-changed' && (
        <div className="flash warn banner">
          <span><strong>{loginFrom(peer.address)}'s key changed.</strong> <Tip align="start">They may have a new device or reset their account, or someone may be impersonating them. Compare safety numbers before you trust it.</Tip></span>
          <button className="btn sm" onClick={() => setVerify(peer.address)}>Review</button>
        </div>
      )}
      {peerLeft && (
        <div className="flash warn banner">
          <span><strong>{title} left this chat.</strong></span>
          {session.isOwner(live!) && <button className="btn danger sm" disabled={busy} onClick={() => confirm(CLOSE_CONFIRM) && run(() => session.closeChat(live!))}>Close chat</button>}
        </div>
      )}
      {!live && (
        <div className="flash banner">
          <span>
            <strong>{group ? 'This chat is no longer available.' : `${last.ended ? endedText(session, last.ended, dm) : 'This chat has ended'}.`}</strong>{' '}
            <Tip align="start">{group ? "GitHub doesn't let you open it right now. If access comes back, it carries on." : 'Your copy of the messages stays here until you delete it.'}</Tip>
          </span>
          <span className="row">
            {dm && peerAddr && !session.blocked.has(peerAddr) && <button className="btn primary sm" disabled={busy} onClick={startNew}>Start a new chat with {title}</button>}
            <button className="btn sm" disabled={busy} onClick={() => confirm(DELETE_CONFIRM(dm ? title : undefined)) && run(async () => { await session.deleteHistory(convo.key); go('/'); })}>Delete chat</button>
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
          {items.map((it, i) => {
            if (it.kind === 'divider') return <div key={it.id} className="sys divider">{it.text}</div>;
            let prevMsg: Item | undefined;
            for (let j = i - 1; j >= 0 && !prevMsg; j--) if (items[j]!.kind === 'msg') prevMsg = items[j];
            const newDay = prevMsg?.kind !== 'msg' || dayKey(prevMsg.m.ts) !== dayKey(it.m.ts);
            const first = !sameRun(items[i - 1], it);
            const last = !sameRun(it, items[i + 1]);
            return (
              <Fragment key={`${it.m.groupId}/${it.m.id}`}>
                {newDay && <div className="day-divider" role="separator"><span>{dayLabel(it.m.ts)}</span></div>}
                <Message m={it.m} session={session} group={it.group} showAuthor={!dm} first={first} last={last} />
              </Fragment>
            );
          })}
          {sending.map((p) => (
            <div key={p.id} className="msg mine">
              <div className="bubble-line"><div className="bubble pending">{p.body}</div></div>
              <span className="msg-meta"><span className="spinner sm" /> Sending…</span>
            </div>
          ))}
          {live && !joined && !peerLeft && pending.length > 0 && (
            <div className="sys">Waiting for {pending.map((a) => '@' + loginFrom(a)).join(', ')} to accept</div>
          )}
        </div>
      </div>
      {live ? (
        <Composer session={session} group={live} disabledReason={peerLeft ? `${title} left this chat` : !joined ? 'Waiting for them to join…' : undefined} error={err} />
      ) : (
        <div className="composer ended">This chat has ended</div>
      )}
      {verify && <VerifyModal session={session} address={verify} onClose={() => setVerify(undefined)} />}
    </>
  );
}

const CLOSE_CONFIRM = 'Close this chat? It ends for everyone and its repo is deleted from GitHub. Everyone keeps the messages their app has, unless they delete them.';
const QUIT_CONFIRM = 'Quit this chat? You stop receiving messages. Your copy of the history stays here until you delete it.';
const DELETE_CONFIRM = (peer?: string) => `Delete this chat's messages from this browser? ${peer ?? 'The other members'} keep${peer ? 's' : ''} their copy.`;

function TrustBadge({ peer, onClick }: { peer: PeerInfo; onClick: () => void }) {
  if (peer.status === 'none' || peer.status === 'error') return null;
  if (peer.status === 'key-changed') return <button className="trust warn" aria-label="Key changed" title="Key changed. Review safety numbers." onClick={onClick}>{Icon.shield(false)}</button>;
  return peer.verified ? (
    <button className="trust ok" aria-label="Verified" title="Verified" onClick={onClick}>{Icon.shield(true)}</button>
  ) : (
    <button className="trust" aria-label="Unverified. Compare safety numbers" title="Not verified yet. Compare safety numbers." onClick={onClick}>{Icon.shield(false)}</button>
  );
}

function Message({ m, session, group, showAuthor, first = true, last = true }: { m: MsgRecord; session: Session; group?: Group; showAuthor: boolean; first?: boolean; last?: boolean }) {
  // Older notes carried a second, explanatory sentence; show only the first.
  if (m.kind === 'system') return <div className="sys">{m.body?.replace(/\. The chat opens for them when they accept in this app\.$/, '')}</div>;
  const who = loginFrom(m.from);
  const reactions = Object.entries(m.reactions ?? {});
  const act = (fn: () => Promise<unknown>) => fn().catch((e) => alert(describeError(e)));
  const canAct = !m.deleted && !!group?.active;
  return (
    <div className={`msg${m.mine ? ' mine' : ''}${first ? '' : ' cont'}`}>
      {!m.mine && last && <span className="msg-avatar"><Avatar name={who} login={who} size="sm" /></span>}
      {showAuthor && !m.mine && first && <span className="msg-author">{who}</span>}
      <div className="bubble-line">
        <div className={`bubble${m.deleted ? ' deleted' : ''}`} title={new Date(m.ts).toLocaleString()}>
          {m.deleted ? 'Message deleted' : m.kind === 'attachment' && m.file ? (group ? <FileView session={session} group={group} file={m.file} caption={m.caption} /> : <span className="muted">📎 {m.file.name ?? 'file'} (no longer available)</span>) : m.body}
        </div>
        {canAct && (
          <span className="msg-actions" role="toolbar" aria-label="Message actions">
            {EMOJI.map((e) => (
              <button key={e} onClick={() => act(() => session.react(group!, m.id, e))} aria-label={`React ${e}`}>{e}</button>
            ))}
            {m.mine && <button className="del" onClick={() => confirm('Delete this message for everyone?') && act(() => session.deleteMessage(group!, m.id))}>Delete</button>}
          </span>
        )}
      </div>
      {reactions.length > 0 && (
        <div className="reactions">
          {reactions.map(([e, who]) => (
            <button key={e} className={`reaction${who.includes(session.address) ? ' me' : ''}`} title={who.map(loginFrom).join(', ')} disabled={!group?.active} onClick={() => group && act(() => session.react(group, m.id, e))}>
              {e} <span>{who.length}</span>
            </button>
          ))}
        </div>
      )}
      {(last || m.edited) && (
        <span className="msg-meta">
          {last && msgTime(m.ts)}
          {m.edited && (last ? ' · edited' : 'Edited')}
        </span>
      )}
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
        <button className="btn icon ghost round" aria-label="Attach file" title="Attach file" disabled={!!disabledReason || busy} onClick={() => fileRef.current?.click()}>{Icon.clip()}</button>
        <input ref={fileRef} type="file" hidden onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = '';
          if (f) void run(() => session.sendFile(group, f));
        }} />
        <div className="composer-field">
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
        </div>
        <button className="btn send round" onClick={send} disabled={!!disabledReason || !text.trim()} aria-label="Send" title="Send (Enter). Shift+Enter for a new line">{Icon.send()}</button>
      </div>
    </div>
  );
}

/** The ⋯ overlay: who is in the chat and what you can do with it. A popover on wide screens, a sheet on phones. */
function ChatMenu({ session, convo, group, peer: peerInfo, onClose, onVerify }: { session: Session; convo: Convo; group?: Group; peer?: PeerInfo; onClose: () => void; onVerify: (a: string) => void }) {
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
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    // Close on a click anywhere else (the chat list keeps working while it's open).
    const out = (e: PointerEvent) => {
      const t = e.target as Element | null;
      if (!t?.closest?.('.chat-menu, [data-menu-toggle], .modal-back')) onClose();
    };
    addEventListener('keydown', k);
    addEventListener('pointerdown', out);
    ref.current?.focus();
    return () => {
      removeEventListener('keydown', k);
      removeEventListener('pointerdown', out);
    };
  }, [onClose]);
  const others = members.filter((m) => m.address !== session.address);
  return (
    <>
      <div className="menu-back" />
      <div className="chat-menu" role="dialog" aria-label={`${convo.title} options`} ref={ref} tabIndex={-1}>
        <div className="menu-head">
          <Avatar name={convo.title} login={peer ? loginFrom(peer) : undefined} square={!dm} size="xl" />
          <div className="menu-title">
            <strong>{convo.title}</strong>
            <span className="small muted">{dm ? (peer ? `@${loginFrom(peer)}` : '') : `${members.length} ${members.length === 1 ? 'member' : 'members'}`}</span>
          </div>
          <button className="btn icon ghost" onClick={onClose} aria-label="Close options">{Icon.close()}</button>
        </div>
        <ErrorFlash error={error} />

        {dm ? (
          peer && peerInfo && peerInfo.status !== 'none' && peerInfo.status !== 'error' && (
            <div className="menu-group">
              <button className="menu-item" onClick={() => onVerify(peer)}>
                <span className={`menu-ico${peerInfo.verified ? ' ok' : peerInfo.status === 'key-changed' ? ' warn' : ''}`}>{Icon.shield(!!peerInfo.verified)}</span>
                <span className="grow">{peerInfo.status === 'key-changed' ? 'Key changed: review' : peerInfo.verified ? 'Verified' : 'Verify safety number'}</span>
                <span className="small muted">{others[0] ? `${others[0].devices.length} ${others[0].devices.length === 1 ? 'device' : 'devices'}` : ''}</span>
              </button>
            </div>
          )
        ) : (
          <>
            {iAmAdmin && live && (
              <form className="menu-inline" onSubmit={(e) => { e.preventDefault(); void run(() => session.rename(live, name.trim())); }}>
                <label className="sr" htmlFor="group-name">Group name</label>
                <input id="group-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Group name" />
                <button className="btn sm" disabled={busy || !name.trim() || name.trim() === live.name}>Rename</button>
              </form>
            )}
            <div className="section-label">Members</div>
            <div className="menu-group">
              {members.map((m) => {
                const login = loginFrom(m.address);
                const me = m.address === session.address;
                return (
                  <div className="member" key={m.fingerprint}>
                    <Avatar name={login} login={login} size="sm" />
                    <div className="grow row" style={{ gap: 6, flexWrap: 'nowrap' }}>
                      <strong className="ellipsis">{login}</strong>{me && <span className="muted">you</span>}
                      {m.admin && <span className="label blue">Admin</span>}
                    </div>
                    {!me && <button className="btn link small" onClick={() => onVerify(m.address)}>Verify</button>}
                    {!me && iAmAdmin && live && (
                      <button className="btn danger sm" disabled={busy} onClick={() => confirm(`Remove ${login} from the group? Keys rotate right away.`) && run(() => session.removeMember(live, m.fingerprint))}>Remove</button>
                    )}
                  </div>
                );
              })}
              {pending.map((a) => (
                <div className="member" key={a}>
                  <Avatar name={loginFrom(a)} login={loginFrom(a)} size="sm" />
                  <div className="grow"><strong>{loginFrom(a)}</strong> <span className="small muted">invited</span></div>
                </div>
              ))}
            </div>
            {iAmAdmin && live && (
              <form className="menu-inline" onSubmit={(e) => { e.preventDefault(); void run(async () => { await session.invite(live, invite); setInvite(''); }); }}>
                <label className="sr" htmlFor="group-invite">Invite someone</label>
                <input id="group-invite" className="input" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="Add by GitHub username" autoComplete="off" />
                <button className="btn primary sm" disabled={busy || !invite.trim()}>{busy ? <span className="spinner sm" /> : 'Invite'}</button>
              </form>
            )}
          </>
        )}

        {group && (
          <div className="menu-group">
            <div className="menu-row">
              <a className="menu-item" href={`https://github.com/${group.space}`} target="_blank" rel="noreferrer">
                <span className="menu-ico">{Icon.lock()}</span>
                <span className="grow">Encrypted repo on GitHub</span>
                <span className="muted">{Icon.external()}</span>
              </a>
              <Tip align="end">Messages are stored in <code>{group.space}</code> as ciphertext. Key epoch {String(group.epoch)}; keys rotate every 7 days or 100 messages, and whenever someone leaves.</Tip>
            </div>
          </div>
        )}

        <div className="menu-group">
          <div className="menu-row">
            <button className="menu-item" disabled={busy} onClick={() => confirm(DELETE_CONFIRM(dm ? convo.title : undefined)) && run(async () => { await session.deleteHistory(convo.key); onClose(); if (!live) go('/'); })}>
              <span className="menu-ico">{Icon.trash()}</span>
              <span className="grow">Delete chat</span>
            </button>
            <Tip align="end">Deletes the messages in this browser only.{live ? ' The chat stays open.' : ''}</Tip>
          </div>
          {live && owner && (
            <div className="menu-row">
              <button className="menu-item danger" disabled={busy} onClick={() => confirm(CLOSE_CONFIRM) && run(async () => { await session.closeChat(live); onClose(); })}>
                <span className="menu-ico">{Icon.close()}</span>
                <span className="grow">Close chat</span>
              </button>
              <Tip align="end">Ends it for everyone and deletes its repo. You started it, so only you can close it.</Tip>
            </div>
          )}
          {live && !owner && (
            <div className="menu-row">
              <button className="menu-item danger" disabled={busy} onClick={() => confirm(QUIT_CONFIRM) && run(async () => { await session.quitChat(live); onClose(); })}>
                <span className="menu-ico">{Icon.leave()}</span>
                <span className="grow">Quit chat</span>
              </button>
              <Tip align="end">You leave; {dm ? `${convo.title} keeps` : 'the others keep'} the chat.</Tip>
            </div>
          )}
          {dm && peer && (blocked ? (
            <button className="menu-item" disabled={busy} onClick={() => run(() => session.unblock(peer))}>
              <span className="menu-ico">{Icon.block()}</span><span className="grow">Unblock {convo.title}</span>
            </button>
          ) : (
            <button className="menu-item danger" disabled={busy} onClick={() => confirm(`Block ${convo.title}? ${live ? (owner ? 'This chat is closed, and ' : 'You quit this chat, and ') : ''}their invitations are turned down without asking you.`) && run(() => session.block(peer))}>
              <span className="menu-ico">{Icon.block()}</span><span className="grow">Block {convo.title}</span>
            </button>
          ))}
        </div>
      </div>
    </>
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
