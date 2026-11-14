import { useEffect, useState } from 'react';
import { loginFrom, type Convo, type PeerInfo, type Session } from '../lib/session';
import { ask, Avatar, ErrorFlash, go, Hint, Icon, Menu, MenuItem, Modal, toast, useAction } from '../ui';

export const CLOSE_ASK = { title: 'Close this chat?', body: 'It ends for everyone and its repo is deleted from GitHub. Everyone keeps the messages their app already has.', confirm: 'Close chat', danger: true };
export const deleteAsk = (peer?: string) => ({ title: 'Delete this chat?', body: `Your copy of the messages is deleted from your browsers. ${peer ?? 'The other members'} keep${peer ? 's' : ''} their copy.`, confirm: 'Delete chat', danger: true });
const QUIT_ASK = { title: 'Quit this chat?', body: 'You stop receiving messages. Your copy of the history stays until you delete it.', confirm: 'Quit chat', danger: true };

/** The "…" button of a chat: info, verify, delete, close or quit, block. Used in the chat list and the chat header. */
export function ChatMenu({ session, convo, className }: { session: Session; convo: Convo; className?: string }) {
  const [info, setInfo] = useState(false);
  const [verify, setVerify] = useState<string>();
  const dm = convo.dm;
  const live = convo.live;
  const peer = convo.peer;
  const owner = !!live && session.isOwner(live);
  const blocked = !!peer && session.blocked.has(peer);
  const act = (fn: () => Promise<unknown>) => void fn().catch((e) => toast(e instanceof Error ? e.message : String(e)));
  return (
    <>
      <Menu label="Chat options" className={className}>
        {(close) => {
          const pick = (fn: () => void) => () => { close(); fn(); };
          return (
            <>
              <MenuItem icon={dm ? Icon.info() : Icon.people()} onClick={pick(() => setInfo(true))}>{dm ? 'Chat info' : 'Members'}</MenuItem>
              {dm && peer && <MenuItem icon={Icon.shield(true, 16)} onClick={pick(() => setVerify(peer))}>Verify {convo.title}</MenuItem>}
              <div className="menu-sep" role="separator" />
              <MenuItem icon={Icon.trash()} onClick={pick(() => act(async () => {
                if (!(await ask(deleteAsk(dm ? convo.title : undefined)))) return;
                await session.deleteHistory(convo.key);
                if (!live) go('/');
              }))}>Delete chat</MenuItem>
              {live && owner && (
                <MenuItem danger icon={Icon.close()} onClick={pick(() => act(async () => { if (await ask(CLOSE_ASK)) await session.closeChat(live); }))}>Close chat</MenuItem>
              )}
              {live && !owner && (
                <MenuItem danger icon={Icon.exit()} onClick={pick(() => act(async () => { if (await ask(QUIT_ASK)) await session.quitChat(live); }))}>Quit chat</MenuItem>
              )}
              {dm && peer && (blocked ? (
                <MenuItem icon={Icon.block()} onClick={pick(() => act(() => session.unblock(peer)))}>Unblock {convo.title}</MenuItem>
              ) : (
                <MenuItem danger icon={Icon.block()} onClick={pick(() => act(async () => {
                  const body = `${live ? (owner ? 'This chat is closed, and their' : 'You quit this chat, and their') : 'Their'} invitations are turned down without asking you.`;
                  if (await ask({ title: `Block ${convo.title}?`, body, confirm: `Block ${convo.title}`, danger: true })) await session.block(peer);
                }))}>Block {convo.title}</MenuItem>
              ))}
            </>
          );
        }}
      </Menu>
      {info && <ChatInfo session={session} convo={convo} onClose={() => setInfo(false)} onVerify={(a) => { setInfo(false); setVerify(a); }} />}
      {verify && <VerifyModal session={session} address={verify} onClose={() => setVerify(undefined)} />}
    </>
  );
}

/** Who is in the chat and where it is stored. Admins of a group rename, invite and remove here. */
function ChatInfo({ session, convo, onClose, onVerify }: { session: Session; convo: Convo; onClose: () => void; onVerify: (a: string) => void }) {
  const dm = convo.dm;
  const live = convo.live;
  const group = live ?? convo.current;
  const members = group?.members() ?? [];
  const iAmAdmin = !!group && group.policy.admins.includes(session.identity!.fingerprint);
  const pending = live ? session.pending(live) : [];
  const [invite, setInvite] = useState('');
  const [name, setName] = useState(group?.name ?? '');
  const { busy, error, run } = useAction();
  return (
    <Modal title={dm ? 'Chat info' : 'Members'} onClose={onClose}>
      <ErrorFlash error={error} />
      {!dm && iAmAdmin && live && (
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); void run(() => session.rename(live, name.trim())); }}>
          <label className="sr" htmlFor="group-name">Group name</label>
          <input id="group-name" className="input" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="btn" disabled={busy || !name.trim() || name.trim() === live.name}>Rename</button>
        </form>
      )}
      <div className="members">
        {members.map((m) => {
          const login = loginFrom(m.address);
          const me = m.address === session.address;
          return (
            <div className="member" key={m.fingerprint}>
              <Avatar name={login} login={login} />
              <div className="member-text">
                <div className="member-name">
                  <strong>{login}</strong>{me && <span className="muted">you</span>}
                  {m.admin && !dm && <span className="label blue">Admin</span>}
                </div>
                <div className="small muted">{m.devices.length} {m.devices.length === 1 ? 'device' : 'devices'}</div>
              </div>
              {!me && <button className="btn" onClick={() => onVerify(m.address)}>Verify</button>}
              {!me && !dm && iAmAdmin && live && (
                <button className="btn danger" disabled={busy} onClick={() => run(async () => {
                  if (await ask({ title: `Remove ${login}?`, body: 'Keys rotate right away, so they can\'t read new messages.', confirm: 'Remove', danger: true })) await session.removeMember(live, m.fingerprint);
                })}>Remove</button>
              )}
            </div>
          );
        })}
        {pending.map((a) => (
          <div className="member" key={a}>
            <Avatar name={loginFrom(a)} login={loginFrom(a)} />
            <div className="member-text"><strong>{loginFrom(a)}</strong><div className="small muted">Invited</div></div>
          </div>
        ))}
      </div>
      {!dm && iAmAdmin && live && (
        <form className="inline-form" onSubmit={(e) => { e.preventDefault(); void run(async () => { await session.invite(live, invite); setInvite(''); }); }}>
          <label className="sr" htmlFor="invite-login">Invite someone</label>
          <input id="invite-login" className="input" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="Invite by GitHub username" autoComplete="off" />
          <button className="btn primary" disabled={busy || !invite.trim()}>{busy ? <span className="spinner" /> : 'Invite'}</button>
        </form>
      )}
      {group && (
        <dl className="facts">
          <div>
            <dt>Stored in</dt>
            <dd><a href={`https://github.com/${group.space}`} target="_blank" rel="noreferrer" className="mono">{group.space}</a> <Hint text="A private GitHub repo. The files in it are ciphertext." /></dd>
          </div>
          <div>
            <dt>Key epoch</dt>
            <dd>{String(group.epoch)} <Hint text="Keys rotate every 7 days or 100 messages, and whenever someone leaves." /></dd>
          </div>
        </dl>
      )}
    </Modal>
  );
}

export function VerifyModal({ session, address, onClose }: { session: Session; address: string; onClose: () => void }) {
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
            <div className="flash warn">{login}'s identity key changed. Compare the new number before you accept it.</div>
          )}
          <p className="verify-lead">
            Compare with {login} in person or on a call.{' '}
            <Hint text={<>If the numbers match on both screens, nobody is in the middle. Their key fingerprint: <span className="mono">{p.fingerprint?.slice(0, 32)}…</span></>} />
          </p>
          <div className="safety">{p.safety?.split(' ').map((g, i) => <span key={i}>{g}</span>)}</div>
          <ErrorFlash error={error} />
          {p.status === 'key-changed' ? (
            <button className="btn primary block" disabled={busy} onClick={() => run(() => session.acceptKeyChange(address))}>Numbers match, accept the new key</button>
          ) : p.verified ? (
            <div className="verified-note">{Icon.shield(true, 16)} Verified</div>
          ) : (
            <button className="btn primary block" disabled={busy} onClick={() => run(() => session.markVerified(address))}>Numbers match, mark as verified</button>
          )}
        </>
      )}
    </Modal>
  );
}
