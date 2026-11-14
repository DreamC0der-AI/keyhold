import { useEffect, useMemo, useState } from 'react';
import { loginFrom, type Convo, type PendingInvite, type Session } from '../lib/session';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, Tip, useAction, useSession } from '../ui';
import { Conversation } from './Conversation';

export function Home({ session, route }: { session: Session; route: string }) {
  useSession(session);
  const chatId = route.startsWith('/c/') ? decodeURIComponent(route.slice(3)) : undefined;
  const convo = chatId ? session.convo(chatId) : undefined;
  const [modal, setModal] = useState<'dm' | 'group'>();
  const [q, setQ] = useState('');

  useEffect(() => {
    session.setActive(convo?.key);
    return () => session.setActive(undefined);
  }, [convo?.key]);

  const convos = session.conversations();
  const unread = convos.reduce((n, c) => n + c.unread, 0);
  useEffect(() => {
    document.title = unread ? `(${unread}) Keyhold Chat` : 'Keyhold Chat';
  }, [unread]);

  const shown = useMemo(
    () => convos.filter((c) => !q || c.title.toLowerCase().includes(q.toLowerCase())),
    [convos, q, session.getVersion()],
  );

  return (
    <div className={`app main${convo || chatId ? ' has-chat' : ''}`}>
      <nav className="sidebar" aria-label="Chats">
        <div className="sidebar-head">
          <div className="sidebar-top">
            <a href="#/" className="logo" aria-label="Chats home">{Icon.logo()}</a>
            <h1 className="sidebar-title">Chats</h1>
            <SyncDot session={session} />
            <span className="spacer" />
            <button className="btn icon ghost" aria-label="New group" title="New group" onClick={() => setModal('group')}>{Icon.people()}</button>
            <button className="btn icon ghost" aria-label="New chat" title="New chat" onClick={() => setModal('dm')}>{Icon.compose()}</button>
            <a href="#/settings" className="me" aria-label="Account and devices" title="Account and devices"><Avatar name={session.login} login={session.login} size="sm" /></a>
          </div>
          <div className="search">
            {Icon.search()}
            <label className="sr" htmlFor="q">Search chats</label>
            <input id="q" type="search" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>
        <ul className="chat-list">
          <SyncNotice session={session} />
          <Invites session={session} />
          {shown.map((c) => <ChatRow key={c.key} session={session} c={c} active={c.key === convo?.key} />)}
          {!convos.length && !session.pendingInvites().length && (
            <li className="empty list-empty">
              <p>No chats yet</p>
              <button className="btn primary" onClick={() => setModal('dm')}>Start a chat</button>
            </li>
          )}
          {!!convos.length && !shown.length && <li className="empty list-empty"><p>No chats match “{q}”</p></li>}
        </ul>
      </nav>
      <main className="content">
        {convo ? (
          <Conversation key={convo.key} session={session} convo={convo} />
        ) : chatId ? (
          <div className="empty"><p>This chat isn't on this browser.</p><a href="#/">Back to chats</a></div>
        ) : (
          <div className="empty">
            <span className="empty-icon">{Icon.lock(28)}</span>
            <h3>Pick a chat or start a new one</h3>
            <button className="btn primary" onClick={() => setModal('dm')}>New chat</button>
          </div>
        )}
      </main>
      {modal === 'dm' && <NewDm session={session} onClose={() => setModal(undefined)} onGroup={() => setModal('group')} />}
      {modal === 'group' && <NewGroup session={session} onClose={() => setModal(undefined)} />}
    </div>
  );
}

function ChatRow({ session, c, active }: { session: Session; c: Convo; active: boolean }) {
  const last = c.rooms[c.rooms.length - 1]!;
  const pending = c.live ? session.pending(c.live) : [];
  const waiting = c.dm && pending.length > 0;
  const preview = c.lastText
    ?? (!c.live ? (last.ended ? endedText(session, last.ended, c.dm) : 'No longer available')
      : waiting ? 'Invitation sent' : 'No messages yet');
  return (
    <li>
      <button className={`chat-item${active ? ' active' : ''}${c.unread ? ' unread' : ''}${!c.live ? ' ended' : ''}`} onClick={() => go(`/c/${encodeURIComponent(c.key)}`)}>
        <Avatar name={c.title} login={c.peer ? loginFrom(c.peer) : undefined} square={!c.dm} size="lg" />
        <span className="name"><span>{c.title}</span></span>
        <span className="time">{timeLabel(c.lastTs)}</span>
        <span className="preview">{preview}</span>
        {!!c.unread && <span className="counter" aria-label={`${c.unread} unread`}>{c.unread}</span>}
      </button>
    </li>
  );
}

/** One line on how a room ended, for the chat list and the divider in the timeline. */
export function endedText(session: Session, e: NonNullable<import('../lib/session').ChatRecord['ended']>, dm: boolean) {
  const me = e.by === session.address;
  const who = e.by ? `@${loginFrom(e.by)}` : 'Someone';
  const what = dm ? 'this chat' : 'this group';
  switch (e.how) {
    case 'closed': return me ? `You closed ${what}` : `${who} closed ${what}`;
    case 'moved': return 'Continued in a newer chat';
    case 'quit': return `You left ${what}`;
    case 'removed': return `You were removed from ${what}`;
  }
}

function Invites({ session }: { session: Session }) {
  const list = session.pendingInvites();
  if (!list.length) return null;
  return (
    <li className="invites">
      <div className="section-label">Invitations</div>
      {list.map((inv) => <InviteRow key={inv.key} session={session} inv={inv} />)}
    </li>
  );
}

function InviteRow({ session, inv }: { session: Session; inv: PendingInvite }) {
  const { busy, error, run } = useAction();
  const from = loginFrom(inv.from);
  return (
    <div className="row invite-row">
      <Avatar name={from} login={from} size="lg" />
      <div className="invite-text">
        <div><strong>{from}</strong> invited you</div>
        {inv.status !== 'invited' && (
          <div className="small muted row" style={{ gap: 4, flexWrap: 'nowrap' }}>
            {(inv.status === 'joining' || inv.status === 'waiting') && <span className="spinner sm" />}
            {inv.status === 'joining' ? 'Joining…' : inv.status === 'waiting' ? `Waiting for @${from}` : 'Couldn’t join yet'}
            {inv.status === 'waiting' && <Tip align="start">@{from}'s app confirms your identity the next time they have Keyhold Chat open.</Tip>}
            {inv.status === 'error' && inv.error && <Tip align="start">{inv.error}</Tip>}
          </div>
        )}
        <ErrorFlash error={error} />
        {inv.status === 'invited' && (
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn primary sm" disabled={busy} onClick={() => run(() => session.acceptInvite(inv.key))}>Accept</button>
            <button className="btn sm" disabled={busy} onClick={() => run(() => session.declineInvite(inv.key))}>Decline</button>
          </div>
        )}
        {(inv.status === 'waiting' || inv.status === 'error') && (
          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn sm" onClick={() => session.retryInvite(inv.key)}>Try again</button>
            <button className="btn link small" onClick={() => session.dismissInvite(inv.key)}>Dismiss</button>
          </div>
        )}
      </div>
    </div>
  );
}

/** A small dot beside the title: green when sync is fine. Details live in its tooltip. */
function SyncDot({ session }: { session: Session }) {
  const err = session.lastPollError;
  const text = `${err ? `Sync problem: ${err}` : 'Up to date'}${session.rateRemaining !== undefined ? ` · ${session.rateRemaining.toLocaleString()} GitHub requests left this hour` : ''}`;
  return <span className={`dot${err ? ' warn' : ''}`} title={text} role="status" aria-label={text} />;
}

function SyncNotice({ session }: { session: Session }) {
  const err = session.lastPollError;
  if (!err && session.syncOn) return null;
  return (
    <li className="notice">
      {err ? <><span className="dot warn" /> Can't reach GitHub right now <Tip align="start">{err}</Tip></> : <><span className="dot off" /> Sync across browsers is off <a href="#/settings">Turn on</a></>}
    </li>
  );
}

function NewDm({ session, onClose, onGroup }: { session: Session; onClose: () => void; onGroup: () => void }) {
  const [login, setLogin] = useState('');
  const { busy, error, run } = useAction();
  const theirs = login.trim() ? session.inviteFrom(login) : undefined;
  return (
    <Modal title="New chat" onClose={onClose}>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const key = await session.startDm(login);
            onClose();
            go(`/c/${encodeURIComponent(key)}`);
          });
        }}
      >
        <div className="field">
          <div className="field-label">
            <label htmlFor="new-dm-login">GitHub username</label>
            <Tip align="start">They get a GitHub invitation to a new private repo (like <code>ghchat-3f9a…</code>) on your account. The chat opens for them when they sign in here. Not on Keyhold Chat yet? Send them this page's address.</Tip>
          </div>
          <input id="new-dm-login" className="input" value={login} onChange={(e) => setLogin(e.target.value)} placeholder="octocat" autoFocus autoComplete="off" />
        </div>
        {theirs && (
          <div className="flash">
            <strong>{loginFrom(theirs.from)}</strong> already invited you.{' '}
            <button type="button" className="btn primary" disabled={busy} onClick={() => run(async () => { await session.acceptInvite(theirs.key); onClose(); })}>Accept their invitation</button>
          </div>
        )}
        <ErrorFlash error={error} />
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <button type="button" className="btn link" onClick={onGroup}>New group instead</button>
          <button className="btn primary" disabled={busy || !login.trim()}>{busy ? <><span className="spinner" /> Creating…</> : 'Start chat'}</button>
        </div>
      </form>
    </Modal>
  );
}

function NewGroup({ session, onClose }: { session: Session; onClose: () => void }) {
  const [name, setName] = useState('');
  const [people, setPeople] = useState('');
  const { busy, error, run, setError } = useAction();
  return (
    <Modal title="New group" onClose={onClose}>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const { group, failed } = await session.createGroup(name, people.split(/[\s,]+/));
            if (failed.length) setError(`Group created, but some invites failed: ${failed.join('; ')}`);
            else onClose();
            go(`/c/${encodeURIComponent(group.id)}`);
          });
        }}
      >
        <div className="field">
          <div className="field-label">
            <label htmlFor="new-group-name">Group name</label>
            <Tip align="start">Encrypted. Only members see it, not GitHub.</Tip>
          </div>
          <input id="new-group-name" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekend hikers" autoFocus />
        </div>
        <div className="field">
          <label className="field-label" htmlFor="new-group-people">Invite people</label>
          <input id="new-group-people" className="input" value={people} onChange={(e) => setPeople(e.target.value)} placeholder="GitHub usernames, like alice, bob" autoComplete="off" />
        </div>
        <ErrorFlash error={error} />
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !name.trim()}>{busy ? <><span className="spinner" /> Creating…</> : 'Create group'}</button>
        </div>
      </form>
    </Modal>
  );
}
