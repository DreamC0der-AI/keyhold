import { useEffect, useState } from 'react';
import type { DeviceCertificate } from '@keyhold/chat/identity';
import { signOut } from '../lib/auth';
import { loginFrom, type Session } from '../lib/session';
import { ask, Avatar, ErrorFlash, Hint, Icon, Modal, useAction, useSession } from '../ui';

export function Settings({ session }: { session: Session }) {
  useSession(session);
  const [devices, setDevices] = useState<{ cert: DeviceCertificate; current: boolean }[]>();
  const [revoke, setRevoke] = useState<DeviceCertificate>();
  const [reset, setReset] = useState(false);
  const { error, run } = useAction();
  const load = () => run(async () => setDevices(await session.myDevices()));
  useEffect(() => {
    void load();
  }, []);
  const fp = session.identity?.fingerprint ?? '';

  return (
    <div className="app">
      <div className="page">
        <div className="wide">
          <a href="#/" className="back-link">{Icon.back()} Chats</a>
          <div className="profile">
            <Avatar name={session.login} login={session.login} size="xl" />
            <div>
              <h2>{session.login}</h2>
              <div className="small muted"><span className="mono">{fp.slice(0, 8)} {fp.slice(8, 16)} {fp.slice(16, 24)} {fp.slice(24, 32)}</span> <Hint text="Your identity fingerprint. People you chat with can compare it to check it's really you." /></div>
            </div>
          </div>
          <ErrorFlash error={error} />

          <section className="box">
            <div className="box-header">
              <h3>Devices</h3>
              <Hint text="To use another browser or computer, sign in there and enter your recovery code. It joins your chats on its own, but can't read older messages. Revoking a lost device removes it from every chat the next time a member's app syncs." />
            </div>
            {!devices ? (
              <div className="box-body"><span className="spinner" /></div>
            ) : (
              devices.map(({ cert, current }) => (
                <div className="box-row kv" key={cert.device}>
                  <div>
                    <strong>Browser <span className="mono">{cert.deviceId.slice(0, 6)}</span></strong> {current && <span className="label green">This browser</span>}
                    <div className="small muted">Added {new Date(cert.issuedAt).toLocaleString()}</div>
                  </div>
                  {!current && <button className="btn danger" onClick={() => setRevoke(cert)}>Revoke</button>}
                </div>
              ))
            )}
          </section>

          <SyncBox session={session} />

          {session.blocked.size > 0 && (
            <section className="box">
              <div className="box-header"><h3>Blocked</h3><Hint text="Invitations from blocked people are turned down without asking you." /></div>
              {[...session.blocked].map((a) => (
                <div className="box-row kv" key={a}>
                  <span className="row" style={{ gap: 8 }}><Avatar name={loginFrom(a)} login={loginFrom(a)} size="sm" /> {loginFrom(a)}</span>
                  <button className="btn" onClick={() => run(() => session.unblock(a))}>Unblock</button>
                </div>
              ))}
            </section>
          )}

          <section className="box">
            <div className="box-header"><h3>Storage</h3><Hint text="Everything lives in your own GitHub repos. Decrypted messages are kept only in this browser." /></div>
            <div className="box-row kv"><span>Public keys</span><a className="mono" href={`https://github.com/${session.login}/keyhold-id`} target="_blank" rel="noreferrer">{session.login}/keyhold-id</a></div>
            <div className="box-row kv"><span>Encrypted backup</span><a className="mono" href={`https://github.com/${session.login}/${session.homeRepo}`} target="_blank" rel="noreferrer">{session.login}/{session.homeRepo}</a></div>
            <div className="box-row kv"><span>Chats</span><span className="mono">ghchat-…</span></div>
          </section>

          <section className="box">
            <div className="box-header"><h3>Account</h3></div>
            <div className="box-row kv">
              <span>Sign out <Hint text="Signs out of GitHub here. Your keys stay in this browser, so signing back in picks up where you left off." /></span>
              <button className="btn" onClick={() => { session.stop(); signOut(); location.hash = ''; location.reload(); }}>Sign out</button>
            </div>
            <div className="box-row kv">
              <span>Forget this browser <Hint text="Removes this browser's keys and messages. You'll need your recovery code to come back." /></span>
              <button className="btn danger" onClick={() => run(async () => { if (!(await ask({ title: 'Forget this browser?', body: 'Its keys and message history are deleted. You need your recovery code to use this account here again.', confirm: 'Forget this browser', danger: true }))) return; await session.forgetBrowser(); signOut(); location.hash = ''; location.reload(); })}>Forget</button>
            </div>
            <div className="box-row kv">
              <span>Reset identity <Hint text="Start over with a brand-new identity. Contacts see a key change and your current chats stop working." /></span>
              <button className="btn danger" onClick={() => setReset(true)}>Reset</button>
            </div>
          </section>
        </div>
      </div>
      {revoke && <RevokeModal session={session} cert={revoke} onClose={() => setRevoke(undefined)} onDone={() => { setRevoke(undefined); void load(); }} />}
      {reset && <ResetModal session={session} onClose={() => setReset(false)} />}
    </div>
  );
}

function RevokeModal({ session, cert, onClose, onDone }: { session: Session; cert: DeviceCertificate; onClose: () => void; onDone: () => void }) {
  const [code, setCode] = useState('');
  const { busy, error, run } = useAction();
  return (
    <Modal title="Revoke device" onClose={onClose}>
      <p>Revoking needs your identity key, so enter your recovery code. The device <span className="mono">{cert.deviceId.slice(0, 6)}</span> will be removed from every chat.</p>
      <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Recovery code" aria-label="Recovery code" />
      <ErrorFlash error={error} />
      <button className="btn danger block" disabled={busy || code.trim().length < 20} onClick={() => run(async () => { await session.revokeDevice(cert.device, code); onDone(); })}>
        {busy ? <span className="spinner" /> : 'Revoke device'}
      </button>
    </Modal>
  );
}

function ResetModal({ session, onClose }: { session: Session; onClose: () => void }) {
  const [confirmText, setConfirm] = useState('');
  const { busy, error, run } = useAction();
  return (
    <Modal title="Reset identity" onClose={onClose}>
      <p>This deletes <code>{session.login}/keyhold-id</code> and <code>{session.login}/{session.homeRepo}</code> and this browser's keys. Chat repos stay on GitHub but you can't read them any more.</p>
      <label className="field">Type <code>{session.login}</code> to confirm<input className="input" value={confirmText} onChange={(e) => setConfirm(e.target.value)} /></label>
      <ErrorFlash error={error} />
      <button className="btn danger block" disabled={busy || confirmText.trim().toLowerCase() !== session.login} onClick={() => run(async () => { await session.resetIdentity(); location.hash = ''; location.reload(); })}>
        {busy ? <span className="spinner" /> : 'Delete and start over'}
      </button>
    </Modal>
  );
}

function SyncBox({ session }: { session: Session }) {
  const [code, setCode] = useState('');
  const { busy, error, run } = useAction();
  return (
    <section className="box">
      <div className="box-header">
        <h3>Sync across browsers</h3>
        <Hint text={<>Your chat list, deleted and closed chats, read marks, blocks and declined invitations are kept, encrypted, in <span className="mono">{session.login}/{session.homeRepo}</span>. Your other browsers apply them within about a minute.</>} />
        <span className="spacer" />
        {session.syncOn ? <span className="label green">On</span> : <span className="label">Off</span>}
      </div>
      {session.syncOn ? (
        session.syncError ? <div className="box-row"><div className="flash warn">Sync problem: {session.syncError}</div></div> : null
      ) : (
        <div className="box-row stack">
          <span className="small muted">Enter your recovery code once to turn it on.</span>
          <ErrorFlash error={error} />
          <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Recovery code" aria-label="Recovery code for sync" />
          <button className="btn primary" disabled={busy || code.trim().length < 20} onClick={() => run(() => session.enableSync(code))}>
            {busy ? <span className="spinner" /> : 'Turn on sync'}
          </button>
        </div>
      )}
    </section>
  );
}
