import { Fragment, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { Group } from '@keyhold/chat/index';
import type { AttachmentRef } from '@keyhold/chat/messages';
import { describeError, loginFrom, type Convo, type MsgRecord, type PeerInfo, type Session } from '../lib/session';
import { endedText } from './Home';
import { ask, Avatar, ErrorFlash, go, Hint, Icon, timeLabel, toast, useAction } from '../ui';
import { ChatMenu, CLOSE_ASK, deleteAsk, VerifyModal } from './ChatMenu';

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
        <Avatar name={title} login={peerAddr ? loginFrom(peerAddr) : undefined} square={!dm} size="lg" />
        <div className="who-text">
          <span className="convo-title-row">
            <strong className="convo-title">{title}</strong>
            <Hint className="hint lock" label="End-to-end encrypted" text={<>End-to-end encrypted. Messages are encrypted in this browser before they're saved to GitHub{space ? <>, in <span className="mono">{space.split('/')[1]}</span></> : ''}.</>}>{Icon.lock(12)}</Hint>
          </span>
          {!dm && group && <span className="convo-sub">{group.members().length} {group.members().length === 1 ? 'member' : 'members'}</span>}
        </div>
        <div className="convo-actions">
          {dm && peer && <TrustBadge peer={peer} onClick={() => setVerify(peer.address)} />}
          <ChatMenu session={session} convo={convo} />
        </div>
      </div>
      {peer?.status === 'key-changed' && (
        <div className="flash warn banner">
          <span><strong>{loginFrom(peer.address)}'s identity key changed.</strong> <Hint text="They may have a new device or reset their account, or someone may be impersonating them. Compare safety numbers before you trust it." /></span>
          <button className="btn" onClick={() => setVerify(peer.address)}>Review</button>
        </div>
      )}
      {peerLeft && (
        <div className="flash warn banner">
          <span><strong>{title} left this chat.</strong></span>
          {session.isOwner(live!) && <button className="btn danger" disabled={busy} onClick={() => run(async () => { if (await ask(CLOSE_ASK)) await session.closeChat(live!); })}>Close chat</button>}
        </div>
      )}
      {!live && (
        <div className="flash banner">
          <span>
            <strong>{group ? 'This chat is no longer available.' : `${last.ended ? endedText(session, last.ended, dm) : 'This chat has ended'}.`}</strong>{' '}
            <Hint text={group ? "GitHub doesn't let you open it right now. If access comes back, it carries on." : 'Your copy of the messages stays here until you delete it.'} />
          </span>
          <span className="row">
            {dm && peerAddr && !session.blocked.has(peerAddr) && <button className="btn primary" disabled={busy} onClick={startNew}>Start a new chat with {title}</button>}
            <button className="btn" disabled={busy} onClick={() => run(async () => { if (await ask(deleteAsk(dm ? title : undefined))) { await session.deleteHistory(convo.key); go('/'); } })}>Delete chat</button>
          </span>
        </div>
      )}
      <ErrorFlash error={error} />
      <div
        className="messages"
        ref={listRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
        }}
      >
        <div className="messages-inner">
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
              <span className="msg-meta"><span className="spinner" style={{ width: 10, height: 10 }} /> Sending…</span>
            </div>
          ))}
          {live && !joined && !peerLeft && pending.length > 0 && (
            <div className="sys">Waiting for {pending.map((a) => '@' + loginFrom(a)).join(', ')} to accept</div>
          )}
        </div>
      </div>
      {live ? (
        <Composer session={session} group={live} disabledReason={peerLeft ? `${title} left this chat` : !joined ? 'Waiting for the other person to join…' : undefined} error={err} />
      ) : (
        <div className="composer ended">This chat has ended</div>
      )}
      {verify && <VerifyModal session={session} address={verify} onClose={() => setVerify(undefined)} />}
    </>
  );
}

/** Quiet by default: nothing for a normal chat, a green check once verified, a warning only when the key changed. */
function TrustBadge({ peer, onClick }: { peer: PeerInfo; onClick: () => void }) {
  if (peer.status === 'key-changed') return <button className="btn icon ghost trust warn" aria-label="Key changed" title="Key changed. Review the new safety number." onClick={onClick}>{Icon.shield(false, 16)}</button>;
  if (peer.status !== 'none' && peer.status !== 'error' && peer.verified) return <button className="btn icon ghost trust ok" aria-label="Verified" title="Verified" onClick={onClick}>{Icon.shield(true, 16)}</button>;
  return null;
}

function Message({ m, session, group, showAuthor, first = true, last = true }: { m: MsgRecord; session: Session; group?: Group; showAuthor: boolean; first?: boolean; last?: boolean }) {
  if (m.kind === 'system') return <div className="sys" title={m.body}>{(m.body ?? '').replace(/\. .*$/, '').replace(/\.$/, '')}</div>;
  const who = loginFrom(m.from);
  const reactions = Object.entries(m.reactions ?? {});
  const act = (fn: () => Promise<unknown>) => fn().catch((e) => toast(describeError(e)));
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
            {m.mine && <button className="del" aria-label="Delete message" title="Delete for everyone" onClick={() => act(async () => { if (await ask({ title: 'Delete this message for everyone?', confirm: 'Delete', danger: true })) await session.deleteMessage(group!, m.id); })}>{Icon.trash()}</button>}
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
        <button className="btn icon ghost" aria-label="Attach file" title="Attach file" disabled={!!disabledReason || busy} onClick={() => fileRef.current?.click()}>{Icon.clip()}</button>
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
        <button className="send" onClick={send} disabled={!!disabledReason || !text.trim()} aria-label="Send" title="Send (Enter). Shift+Enter for a new line.">{Icon.send()}</button>
      </div>
    </div>
  );
}
