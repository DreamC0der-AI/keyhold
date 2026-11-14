import { useEffect, useState } from 'react';
import type { DeviceCertificate } from '@keyhold/chat/identity';
import { signOut } from '../lib/auth';
import { loginFrom, type Session } from '../lib/session';
import { Avatar, ErrorFlash, Icon, Modal, Tip, useAction, useSession } from '../ui';

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
      <header className="topbar">
        <a href="#/" className="btn icon ghost" aria-label="Back to chats" title="Back to chats">{Icon.back()}</a>
        <h1 className="topbar-title">Account</h1>
      </header>
      <div className="page">
        <div className="wide">
          <div className="profile">
            <Avatar name={session.login} login={session.login} size="xl" />
            <div>
              <h2>{session.login}</h2>
              <div className="small muted row" style={{ gap: 4 }}>Fingerprint <span className="mono">{fp.slice(0, 8)} {fp.slice(8, 16)} {fp.slice(16, 24)} {fp.slice(24, 32)}</span></div>
            </div>
          </div>
          <ErrorFlash error={error} />

          <section className="box">
            <div className="box-header row">
              <h3>Devices</h3>
              <Tip align="start">To use another browser, sign in there and enter your recovery code. It joins your chats on its own but can't read older messages. Revoking a lost device removes it from every chat the next time a member's app syncs.</Tip>
            </div>
            {!devices ? (
              <div className="box-body"><span className="spinner" /></div>
            ) : (
              devices.map(({ cert, current }) => (
                <div className="box-row row" key={cert.device} style={{ justifyContent: 'space-between' }}>
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
              <div className="box-header row"><h3>Blocked</h3><Tip align="start">Invitations from blocked people are turned down without asking you.</Tip></div>
              {[...session.blocked].map((a) => (
                <div className="box-row row" key={a} style={{ justifyContent: 'space-between' }}>
                  <span className="row" style={{ gap: 8 }}><Avatar name={loginFrom(a)} login={loginFrom(a)} size="sm" /> {loginFrom(a)}</span>
                  <button className="btn" onClick={() => run(() => session.unblock(a))}>Unblock</button>
                </div>
              ))}
            </section>
          )}

          <section className="box">
            <div className="box-header row"><h3>Where your data lives</h3><Tip align="start">Each chat is a private <code>ghchat-…</code> repo. Decrypted messages are kept only in this browser.</Tip></div>
            <a className="box-row link-row" href={`https://github.com/${session.login}/keyhold-id`} target="_blank" rel="noreferrer"><span className="grow">Public keys</span><span className="mono muted">{session.login}/keyhold-id</span></a>
            <a className="box-row link-row" href={`https://github.com/${session.login}/${session.homeRepo}`} target="_blank" rel="noreferrer"><span className="grow">Encrypted identity backup</span><span className="mono muted">{session.login}/{session.homeRepo}</span></a>
          </section>

          <section className="box">
            <div className="box-header"><h3>Session</h3></div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span className="row" style={{ gap: 4 }}>Sign out <Tip align="start">Your keys stay in this browser, so signing back in picks up where you left off.</Tip></span>
              <button className="btn" onClick={() => { session.stop(); signOut(); location.hash = ''; location.reload(); }}>Sign out</button>
            </div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span className="row" style={{ gap: 4 }}>Remove from this browser <Tip align="start">Deletes this browser's keys and messages. You'll need your recovery code to come back.</Tip></span>
              <button className="btn danger" onClick={() => confirm('Delete this browser\'s keys and message history? You need your recovery code to use this account here again.') && run(async () => { await session.forgetBrowser(); signOut(); location.hash = ''; location.reload(); })}>Remove</button>
            </div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span className="row" style={{ gap: 4 }}>Reset identity <Tip align="start">Start over with a brand-new identity. Contacts see a key change and your current chats stop working.</Tip></span>
              <button className="btn danger" onClick={() => setReset(true)}>Reset</button>
            </div>
          </section>
          <p className="small muted center">Keyhold Chat · MLS (RFC 9420) · GitHub is the only backend</p>
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
      <div className="box-header row">
        <h3>Sync across browsers</h3>
        <Tip align="start">Your chat list, deleted and closed chats, read marks, blocks and declined invitations are kept, encrypted, in <span className="mono">{session.login}/{session.homeRepo}</span>. Other browsers apply them within about a minute.</Tip>
        <span className="spacer" />
        {session.syncOn ? <span className="label green">On</span> : <span className="label">Off</span>}
      </div>
      {session.syncOn ? (
        session.syncError ? <div className="box-row"><div className="flash warn">Sync problem: {session.syncError}</div></div> : null
      ) : (
        <div className="box-row stack">
          <span className="small muted">This browser was set up before sync existed. Enter your recovery code once to turn it on.</span>
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
