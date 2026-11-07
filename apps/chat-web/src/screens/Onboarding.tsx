import { useState } from 'react';
import { installUrl } from '../config';
import type { Session } from '../lib/session';
import { ErrorFlash, Icon, useAction } from '../ui';

function Frame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="page">
      <div className="narrow">
        <div className="center stack" style={{ alignItems: 'center', marginTop: 16 }}>
          <span className="logo" style={{ width: 40, height: 40 }}>{Icon.logo()}</span>
          <h2>{title}</h2>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Install({ session }: { session: Session }) {
  return (
    <Frame title="Install the app on your account">
      <div className="box">
        <div className="box-body stack">
          <p>Keyhold Chat keeps each chat in a private repo on your GitHub account. To create those repos it needs the app installed with <strong>Only select repositories</strong>.</p>
          <ol className="steps">
            <li>Open the install page and pick <strong>Only select repositories</strong>.</li>
            <li>GitHub asks for at least one repo. Pick any one; the app never reads it.</li>
            <li>Come back here. New chat repos are added to the install automatically.</li>
          </ol>
          <a className="btn primary block" href={installUrl()} target="_blank" rel="noreferrer">Install on GitHub</a>
          <button className="btn block" onClick={() => session.recheckInstall()}>I've installed it</button>
        </div>
      </div>
      <p className="muted small center">Signed in as <strong>{session.login}</strong></p>
    </Frame>
  );
}

export function NewIdentity({ session }: { session: Session }) {
  const { busy, error, run } = useAction();
  const [code, setCode] = useState<string>();
  const [typed, setTyped] = useState('');
  const last = code?.split('-').pop() ?? '';

  if (!code) {
    return (
      <Frame title="Create your encryption identity">
        <div className="box">
          <div className="box-body stack">
            <ErrorFlash error={error} />
            <p>Your identity is a key made in this browser. It proves who you are to the people you chat with. Its private half never goes to GitHub unencrypted.</p>
            <ul className="steps muted">
              <li>The public key goes to a public repo <code>{session.login}/keyhold-id</code>, so others can find and check it.</li>
              <li>An encrypted backup goes to your private repo <code>{session.login}/keyhold-home</code>.</li>
              <li>You get a recovery code. It's the only way to open the backup on a new device.</li>
            </ul>
            <button className="btn primary block" disabled={busy} onClick={() => run(async () => setCode(await session.createIdentity()))}>
              {busy ? <><span className="spinner" /> Creating keys…</> : 'Create identity'}
            </button>
          </div>
        </div>
      </Frame>
    );
  }
  return (
    <Frame title="Save your recovery code">
      <div className="box">
        <div className="box-body stack">
          <p>Write this down or keep it in a password manager. You need it to use your account on another browser or after clearing this one. Nobody can reset it for you.</p>
          <div className="code-box">{code}</div>
          <button className="btn" onClick={() => navigator.clipboard?.writeText(code)}>Copy</button>
          <label className="field">
            Type the last block to confirm you saved it
            <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value.toUpperCase())} placeholder={'XXXX'} maxLength={4} />
          </label>
          <ErrorFlash error={error} />
          <button className="btn primary block" disabled={typed.trim() !== last || busy} onClick={() => run(() => session.finishSetup())}>
            Continue to chats
          </button>
        </div>
      </div>
    </Frame>
  );
}

export function Restore({ session }: { session: Session }) {
  const { busy, error, run } = useAction();
  const [code, setCode] = useState('');
  const [reset, setReset] = useState(false);
  const [confirm, setConfirm] = useState('');
  return (
    <Frame title="Add this browser to your account">
      <div className="box">
        <div className="box-body stack">
          <p><strong>{session.login}</strong> already has an identity. Enter your recovery code to use it here.</p>
          <ErrorFlash error={error} />
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => session.restoreIdentity(code));
            }}
          >
            <label className="field">
              Recovery code
              <input className="input mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" autoFocus />
            </label>
            <button className="btn primary block" disabled={busy || code.trim().length < 20}>
              {busy ? <><span className="spinner" /> Opening backup…</> : 'Add this browser'}
            </button>
          </form>
          <p className="muted small">This browser joins your chats by itself. It can't read messages sent before it joined.</p>
        </div>
      </div>
      <div className="box">
        <div className="box-body stack">
          {!reset ? (
            <button className="btn link" onClick={() => setReset(true)}>Lost your recovery code?</button>
          ) : (
            <>
              <p>You can start over with a new identity. Your contacts will see that your key changed, and your current chats stop working for you.</p>
              <label className="field">
                Type <code>{session.login}</code> to delete <code>keyhold-id</code> and <code>keyhold-home</code>
                <input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              </label>
              <button
                className="btn danger block"
                disabled={confirm.trim().toLowerCase() !== session.login || busy}
                onClick={() => run(async () => { await session.resetIdentity(); location.reload(); })}
              >
                Start over with a new identity
              </button>
            </>
          )}
        </div>
      </div>
    </Frame>
  );
}
