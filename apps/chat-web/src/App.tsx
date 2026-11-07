import { useEffect, useState } from 'react';
import { finishWebFlow, loadAuth, signOut, type AuthState } from './lib/auth';
import { Session } from './lib/session';
import { SignIn } from './screens/SignIn';
import { Install, NewIdentity, Restore } from './screens/Onboarding';
import { Home } from './screens/Home';
import { Settings } from './screens/Settings';
import { ErrorFlash, useHash, useSession } from './ui';

export function App() {
  const [auth, setAuth] = useState<AuthState | undefined>();
  const [booting, setBooting] = useState(true);
  const [error, setError] = useState<string>();

  useEffect(() => {
    finishWebFlow()
      .then((a) => setAuth(a ?? loadAuth()))
      .catch((e) => {
        setError(e instanceof Error ? e.message : String(e));
        setAuth(loadAuth());
      })
      .finally(() => setBooting(false));
  }, []);

  if (booting) return <Loading />;
  if (!auth) return <SignIn onSignedIn={setAuth} initialError={error} />;
  return <Signed key={auth.id} auth={auth} onSignOut={() => { signOut(); setAuth(undefined); }} />;
}

function Signed({ auth, onSignOut }: { auth: AuthState; onSignOut: () => void }) {
  const [session] = useState(() => new Session(auth));
  useEffect(() => {
    void session.start();
    return () => session.stop();
  }, [session]);
  useSession(session);
  const route = useHash();

  switch (session.phase) {
    case 'loading':
      return <Loading />;
    case 'error':
      return (
        <div className="page"><div className="narrow">
          <ErrorFlash error={session.error} />
          <button className="btn" onClick={() => location.reload()}>Try again</button>
          <button className="btn" onClick={onSignOut}>Sign out</button>
        </div></div>
      );
    case 'install':
      return <Install session={session} />;
    case 'new-identity':
      return <NewIdentity session={session} />;
    case 'restore':
      return <Restore session={session} />;
    case 'ready':
      return route === '/settings' ? <Settings session={session} /> : <Home session={session} route={route} />;
  }
}

function Loading() {
  return <div className="empty" style={{ height: '100%' }}><span className="spinner" /></div>;
}
