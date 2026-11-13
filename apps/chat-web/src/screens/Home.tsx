import { useEffect, useMemo, useState } from 'react';
import { loginFrom, type Convo, type PendingInvite, type Session } from '../lib/session';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, useAction, useSession } from '../ui';
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
    <div className="app">
      <header className="header">
        <a href="#/" className="logo" aria-label="Chats home">{Icon.logo()}</a>
        <nav className="crumbs" aria-label="Breadcrumb">
          <span className="hide-sm">{session.login}</span>
          <span className="muted hide-sm">/</span>
          {convo ? <><a href="#/">Chats</a><span className="muted">/</span><strong>{convo.title}</strong></> : <strong>Chats</strong>}
        </nav>
        <span className="spacer" />
        <button className="btn icon" aria-label="New chat" title="New chat" onClick={() => setModal('dm')}>{Icon.plus()}</button>
        <a href="#/settings" aria-label="Account and devices" title="Account and devices"><Avatar name={session.login} login={session.login} /></a>
      </header>
      <div className={`main${convo ? ' has-chat' : ''}`}>
        <nav className="sidebar" aria-label="Chats">
          <div className="sidebar-head">
            <label className="sr" htmlFor="q">Search chats</label>
            <input id="q" className="input" type="search" placeholder="Search chats" value={q} onChange={(e) => setQ(e.target.value)} />
            <div className="row" style={{ flexWrap: 'nowrap' }}>
              <button className="btn primary" onClick={() => setModal('dm')}>New</button>
              <button className="btn icon" aria-label="New group" title="New group" onClick={() => setModal('group')}>{Icon.people()}</button>
            </div>
          </div>
          <ul className="chat-list">
            <Invites session={session} />
            {shown.map((c) => <ChatRow key={c.key} session={session} c={c} active={c.key === convo?.key} />)}
            {!convos.length && !session.pendingInvites().length && (
              <li className="empty" style={{ padding: 32 }}>
                <p>No chats yet.</p>
                <button className="btn primary" onClick={() => setModal('dm')}>Start a chat</button>
                <p className="small">When someone invites you, the invitation shows up right here for you to accept.</p>
              </li>
            )}
          </ul>
          <StatusBar session={session} />
        </nav>
        <main className="content">
          {convo ? (
            <Conversation key={convo.key} session={session} convo={convo} />
          ) : chatId ? (
            <div className="empty"><p>This chat isn't on this browser.</p><a href="#/">Back to chats</a></div>
          ) : (
            <div className="empty">
              {Icon.lock(28)}
              <h3 style={{ color: 'var(--fg)' }}>Pick a chat or start a new one</h3>
              <p>Messages are encrypted in this browser before they're saved to GitHub.</p>
            </div>
          )}
        </main>
      </div>
      {modal === 'dm' && <NewDm session={session} onClose={() => setModal(undefined)} onGroup={() => setModal('group')} />}
      {modal === 'group' && <NewGroup session={session} onClose={() => setModal(undefined)} />}
    </div>
  );
}

function ChatRow({ session, c, active }: { session: Session; c: Convo; active: boolean }) {
  const g = c.live ?? c.current;
  const last = c.rooms[c.rooms.length - 1]!;
  const pending = c.live ? session.pending(c.live) : [];
  const waiting = c.dm && pending.length > 0;
  const preview = c.lastText
    ?? (!c.live ? (last.ended ? endedText(session, last.ended, c.dm) : 'This chat is no longer available')
      : waiting ? `Waiting for ${c.title} to join` : 'No messages yet');
  return (
    <li>
      <button className={`chat-item${active ? ' active' : ''}`} onClick={() => go(`/c/${encodeURIComponent(c.key)}`)}>
        <Avatar name={c.title} login={c.peer ? loginFrom(c.peer) : undefined} square={!c.dm} />
        <span className="meta">
          <span className="name">
            <span>{c.title}</span>
            {!c.dm && g && <span className="label">{g.members().length}</span>}
            {waiting && <span className="label">Invite sent</span>}
            {!c.live && <span className="label">Ended</span>}
          </span>
          <span className="preview">{preview}</span>
        </span>
        <span className="right">
          <span>{timeLabel(c.lastTs)}</span>
          {!!c.unread && <span className="counter">{c.unread}</span>}
        </span>
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
    <li style={{ borderBottom: '1px solid var(--border)', background: 'var(--accent-bg)' }}>
      <div className="small" style={{ padding: '8px 16px 0', fontWeight: 600 }}>Invitations</div>
      {list.map((inv) => <InviteRow key={inv.key} session={session} inv={inv} />)}
    </li>
  );
}

function InviteRow({ session, inv }: { session: Session; inv: PendingInvite }) {
  const { busy, error, run } = useAction();
  const from = loginFrom(inv.from);
  const text =
    inv.status === 'invited' ? 'Accept to open the chat. Decline to turn it down on GitHub too.'
    : inv.status === 'joining' ? (inv.space ? 'Joining…' : 'Accepted. Opening the chat…')
    : inv.status === 'waiting' ? `Waiting for @${from}'s app to confirm your identity. This happens as soon as they have Keyhold Chat open.`
    : 'Could not join yet.';
  return (
    <div className="row" style={{ padding: '8px 16px', alignItems: 'flex-start', flexWrap: 'nowrap' }}>
      <Avatar name={from} login={from} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div><strong>{from}</strong> invited you to a chat</div>
        <div className="small muted" title={inv.error}>
          {inv.status === 'joining' || inv.status === 'waiting' ? <span className="spinner" style={{ width: 10, height: 10, marginRight: 4 }} /> : null}
          {text}{inv.error ? ` ${inv.error}` : ''}
        </div>
        <ErrorFlash error={error} />
        {inv.status === 'invited' && (
          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn primary" disabled={busy} onClick={() => run(() => session.acceptInvite(inv.key))}>Accept</button>
            <button className="btn" disabled={busy} onClick={() => run(() => session.declineInvite(inv.key))}>Decline</button>
          </div>
        )}
        {(inv.status === 'waiting' || inv.status === 'error') && (
          <div className="row" style={{ marginTop: 4 }}>
            <button className="btn" onClick={() => session.retryInvite(inv.key)}>Try again</button>
            <button className="btn link small" onClick={() => session.dismissInvite(inv.key)}>Dismiss</button>
          </div>
        )}
      </div>
    </div>
  );
}

function StatusBar({ session }: { session: Session }) {
  const err = session.lastPollError;
  return (
    <div className="status-bar" title={err}>
      <span className={`dot${err ? ' warn' : ''}`} />
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {err ? `Sync problem: ${err}` : 'Up to date'}
        {session.rateRemaining !== undefined && ` · ${session.rateRemaining.toLocaleString()} GitHub requests left this hour`}
      </span>
    </div>
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
        <label className="field">
          GitHub username
          <input className="input" value={login} onChange={(e) => setLogin(e.target.value)} placeholder="octocat" autoFocus autoComplete="off" />
          <span className="hint">They get a GitHub repo invitation. The chat opens for them when they sign in here. Not on Keyhold Chat yet? Send them this page's address.</span>
        </label>
        {theirs && (
          <div className="flash">
            <strong>{loginFrom(theirs.from)}</strong> already invited you. Accept their invitation instead of starting a second chat.{' '}
            <button type="button" className="btn primary" disabled={busy} onClick={() => run(async () => { await session.acceptInvite(theirs.key); onClose(); })}>Accept their invitation</button>
          </div>
        )}
        <ErrorFlash error={error} />
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <button type="button" className="btn link" onClick={onGroup}>New group instead</button>
          <button className="btn primary" disabled={busy || !login.trim()}>{busy ? <><span className="spinner" /> Creating…</> : 'Start chat'}</button>
        </div>
        <p className="muted small">This creates a private repo with a random name (like <code>ghchat-3f9a…</code>) on your account.</p>
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
        <label className="field">
          Group name
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekend hikers" autoFocus />
          <span className="hint">Encrypted. Only members see it, not GitHub.</span>
        </label>
        <label className="field">
          Invite people
          <input className="input" value={people} onChange={(e) => setPeople(e.target.value)} placeholder="alice, bob" autoComplete="off" />
          <span className="hint">GitHub usernames, separated by commas. You can add more later.</span>
        </label>
        <ErrorFlash error={error} />
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !name.trim()}>{busy ? <><span className="spinner" /> Creating…</> : 'Create group'}</button>
        </div>
      </form>
    </Modal>
  );
}
