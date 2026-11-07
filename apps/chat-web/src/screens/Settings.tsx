import { useEffect, useState } from 'react';
import type { DeviceCertificate } from '@keyhold/chat/identity';
import { signOut } from '../lib/auth';
import type { Session } from '../lib/session';
import { Avatar, ErrorFlash, Icon, Modal, useAction, useSession } from '../ui';

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
      <header className="header">
        <a href="#/" className="logo" aria-label="Chats home">{Icon.logo()}</a>
        <nav className="crumbs" aria-label="Breadcrumb"><a href="#/">Chats</a><span className="muted">/</span><strong>Account and devices</strong></nav>
        <span className="spacer" />
      </header>
      <div className="page">
        <div className="wide">
          <div className="row" style={{ gap: 12 }}>
            <Avatar name={session.login} login={session.login} size="lg" />
            <div>
              <h2>{session.login}</h2>
              <div className="small muted">Identity fingerprint <span className="mono">{fp.slice(0, 8)} {fp.slice(8, 16)} {fp.slice(16, 24)} {fp.slice(24, 32)}</span></div>
            </div>
          </div>
          <ErrorFlash error={error} />

          <section className="box">
            <div className="box-header row" style={{ justifyContent: 'space-between' }}>
              <h3>Devices</h3>
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
            <div className="box-row small muted">
              To use another browser or computer, sign in there and enter your recovery code. It joins your chats on its own; it can't read older messages. Revoking a lost device removes it from every chat the next time a member's app syncs.
            </div>
          </section>

          <section className="box">
            <div className="box-header"><h3>Where your data lives</h3></div>
            <div className="box-row small">Public keys: <a className="mono" href={`https://github.com/${session.login}/keyhold-id`} target="_blank" rel="noreferrer">{session.login}/keyhold-id</a></div>
            <div className="box-row small">Encrypted backup of your identity: <a className="mono" href={`https://github.com/${session.login}/keyhold-home`} target="_blank" rel="noreferrer">{session.login}/keyhold-home</a> (private)</div>
            <div className="box-row small">Chats: private <code>ghchat-…</code> repos, one per chat. Decrypted messages are kept only in this browser.</div>
          </section>

          <section className="box">
            <div className="box-header"><h3>Session</h3></div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span>Sign out of GitHub here. Your keys stay in this browser, so signing back in picks up where you left off.</span>
              <button className="btn" onClick={() => { session.stop(); signOut(); location.hash = ''; location.reload(); }}>Sign out</button>
            </div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span>Remove this browser's keys and messages. You'll need your recovery code to come back.</span>
              <button className="btn danger" onClick={() => confirm('Delete this browser\'s keys and message history? You need your recovery code to use this account here again.') && run(async () => { await session.forgetBrowser(); signOut(); location.hash = ''; location.reload(); })}>Remove from this browser</button>
            </div>
            <div className="box-row row" style={{ justifyContent: 'space-between' }}>
              <span>Start over with a brand-new identity. Contacts see a key change and your current chats stop working.</span>
              <button className="btn danger" onClick={() => setReset(true)}>Reset identity</button>
            </div>
          </section>
          <p className="small muted">Keyhold Chat · E2E encrypted with MLS (RFC 9420) · GitHub is the only backend.</p>
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
      <p>This deletes <code>{session.login}/keyhold-id</code> and <code>{session.login}/keyhold-home</code> and this browser's keys. Chat repos stay on GitHub but you can't read them any more.</p>
      <label className="field">Type <code>{session.login}</code> to confirm<input className="input" value={confirmText} onChange={(e) => setConfirm(e.target.value)} /></label>
      <ErrorFlash error={error} />
      <button className="btn danger block" disabled={busy || confirmText.trim().toLowerCase() !== session.login} onClick={() => run(async () => { await session.resetIdentity(); location.hash = ''; location.reload(); })}>
        {busy ? <span className="spinner" /> : 'Delete and start over'}
      </button>
    </Modal>
  );
}
