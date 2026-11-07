import { useEffect, useMemo, useState } from 'react';
import type { Group } from '@keyhold/chat/index';
import { loginFrom, type Session } from '../lib/session';
import { Avatar, ErrorFlash, go, Icon, Modal, timeLabel, useAction, useSession } from '../ui';
import { Conversation } from './Conversation';

export function Home({ session, route }: { session: Session; route: string }) {
  useSession(session);
  const chatId = route.startsWith('/c/') ? decodeURIComponent(route.slice(3)) : undefined;
  const group = chatId ? session.group(chatId) : undefined;
  const [modal, setModal] = useState<'dm' | 'group'>();
  const [q, setQ] = useState('');

  useEffect(() => {
    session.setActive(group?.id);
    return () => session.setActive(undefined);
  }, [group?.id]);

  const groups = session.groups();
  const unread = groups.reduce((n, g) => n + (session.records.get(g.id)?.unread ?? 0), 0);
  useEffect(() => {
    document.title = unread ? `(${unread}) Keyhold Chat` : 'Keyhold Chat';
  }, [unread]);

  const shown = useMemo(
    () => groups.filter((g) => !q || session.title(g).toLowerCase().includes(q.toLowerCase())),
    [groups, q, session.getVersion()],
  );

  return (
    <div className="app">
      <header className="header">
        <a href="#/" className="logo" aria-label="Chats home">{Icon.logo()}</a>
        <nav className="crumbs" aria-label="Breadcrumb">
          <span className="hide-sm">{session.login}</span>
          <span className="muted hide-sm">/</span>
          {group ? <><a href="#/">Chats</a><span className="muted">/</span><strong>{session.title(group)}</strong></> : <strong>Chats</strong>}
        </nav>
        <span className="spacer" />
        <button className="btn icon" aria-label="New chat" title="New chat" onClick={() => setModal('dm')}>{Icon.plus()}</button>
        <a href="#/settings" aria-label="Account and devices" title="Account and devices"><Avatar name={session.login} login={session.login} /></a>
      </header>
      <div className={`main${group ? ' has-chat' : ''}`}>
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
            {shown.map((g) => <ChatRow key={g.id} session={session} g={g} active={g.id === group?.id} />)}
            {!groups.length && (
              <li className="empty" style={{ padding: 32 }}>
                <p>No chats yet.</p>
                <button className="btn primary" onClick={() => setModal('dm')}>Start a chat</button>
                <p className="small">Invitations from others show up here by themselves.</p>
              </li>
            )}
          </ul>
          <StatusBar session={session} />
        </nav>
        <main className="content">
          {group ? (
            <Conversation key={group.id} session={session} group={group} />
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

function ChatRow({ session, g, active }: { session: Session; g: Group; active: boolean }) {
  const r = session.records.get(g.id);
  const dm = session.isDm(g);
  const title = session.title(g);
  const pending = session.pending(g);
  const peer = dm ? session.dmPeer(g) : undefined;
  const waiting = dm && pending.length > 0;
  const preview = !g.active ? 'You are no longer in this chat' : r?.lastText ?? (waiting ? `Waiting for ${title} to join` : 'No messages yet');
  return (
    <li>
      <button className={`chat-item${active ? ' active' : ''}`} onClick={() => go(`/c/${encodeURIComponent(g.id)}`)}>
        <Avatar name={title} login={peer ? loginFrom(peer) : undefined} square={!dm} />
        <span className="meta">
          <span className="name">
            <span>{title}</span>
            {!dm && <span className="label">{g.members().length}</span>}
            {waiting && <span className="label">Invite sent</span>}
          </span>
          <span className="preview">{preview}</span>
        </span>
        <span className="right">
          <span>{r ? timeLabel(r.lastTs) : ''}</span>
          {!!r?.unread && <span className="counter">{r.unread}</span>}
        </span>
      </button>
    </li>
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
  return (
    <Modal title="New chat" onClose={onClose}>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const g = await session.startDm(login);
            onClose();
            go(`/c/${encodeURIComponent(g.id)}`);
          });
        }}
      >
        <label className="field">
          GitHub username
          <input className="input" value={login} onChange={(e) => setLogin(e.target.value)} placeholder="octocat" autoFocus autoComplete="off" />
          <span className="hint">They get a GitHub repo invitation. The chat opens for them when they sign in here. Not on Keyhold Chat yet? Send them this page's address.</span>
        </label>
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
