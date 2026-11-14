import { useEffect, useRef, useState } from 'react';
import { CONFIG } from '../config';
import { mockSignIn, pollDeviceFlow, startDeviceFlow, startWebFlow, type AuthState, type DeviceCode } from '../lib/auth';
import { ErrorFlash, Icon, useAction } from '../ui';

export function SignIn({ onSignedIn, initialError }: { onSignedIn: (a: AuthState) => void; initialError?: string }) {
  const { busy, error, run, setError } = useAction();
  const [device, setDevice] = useState<DeviceCode>();
  const [mockLogin, setMockLogin] = useState('');
  const abort = useRef<AbortController>();

  useEffect(() => {
    if (initialError) setError(initialError);
    return () => abort.current?.abort();
  }, []);

  const deviceFlow = () =>
    run(async () => {
      const code = await startDeviceFlow();
      setDevice(code);
      abort.current = new AbortController();
      try {
        onSignedIn(await pollDeviceFlow(code, abort.current.signal));
      } finally {
        setDevice(undefined);
      }
    });

  return (
    <div className="page">
      <div className="narrow">
        <div className="center stack" style={{ alignItems: 'center', gap: 16, marginTop: 24 }}>
          <span className="logo" style={{ width: 48, height: 48 }}>{Icon.logo()}</span>
          <h1>Sign in to Keyhold Chat</h1>
        </div>
        <div className="box">
          <div className="box-body stack">
            <ErrorFlash error={error} />
            {CONFIG.mock ? (
              <form
                className="stack"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => onSignedIn(await mockSignIn(mockLogin)));
                }}
              >
                <label className="field">
                  Test account
                  <input className="input" value={mockLogin} onChange={(e) => setMockLogin(e.target.value)} placeholder="alice" autoFocus />
                </label>
                <button className="btn primary block" disabled={busy || !mockLogin}>Sign in (test GitHub)</button>
              </form>
            ) : device ? (
              <div className="stack">
                <p>
                  Open <a href={device.verification_uri} target="_blank" rel="noreferrer">{device.verification_uri.replace('https://', '')}</a> and enter this code:
                </p>
                <div className="code-box" aria-live="polite">{device.user_code}</div>
                <div className="row muted small"><span className="spinner" /> Waiting for GitHub…</div>
                <button className="btn" onClick={() => abort.current?.abort()}>Cancel</button>
              </div>
            ) : (
              <>
                <button className="btn primary block" disabled={busy} onClick={() => run(startWebFlow)}>
                  Sign in with GitHub
                </button>
                <button className="btn block" disabled={busy} onClick={deviceFlow}>
                  Sign in with a one-time code instead
                </button>
              </>
            )}
          </div>
        </div>
        <div className="box">
          <div className="box-body stack small">
            <p className="row" style={{ gap: 6, fontWeight: 600 }}>{Icon.lock(14)} End-to-end encrypted, GitHub as the only backend</p>
            <ul className="steps muted">
              <li>Each chat is a private GitHub repo that only its members can open.</li>
              <li>Messages are encrypted in this browser (MLS) before they are saved. GitHub sees only ciphertext and who talks to whom.</li>
              <li>The app only gets access to the repos it creates for you.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
