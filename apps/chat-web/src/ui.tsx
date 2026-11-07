import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react';
import type { Session } from './lib/session';

export function useSession(s: Session) {
  useSyncExternalStore(s.subscribe, s.getVersion);
  return s;
}

export function useHash(): string {
  const [h, setH] = useState(location.hash);
  useEffect(() => {
    const on = () => setH(location.hash);
    addEventListener('hashchange', on);
    return () => removeEventListener('hashchange', on);
  }, []);
  return h.replace(/^#/, '') || '/';
}
export const go = (path: string) => {
  location.hash = path;
};

const TINTS = [
  ['#dafbe1', '#116329'],
  ['#fff1e5', '#953800'],
  ['#fbefff', '#6e40c9'],
  ['#ddf4ff', '#0550ae'],
  ['#fff8c5', '#7d4e00'],
  ['#ffebe9', '#a40e26'],
];
function tint(key: string) {
  let h = 0;
  for (const c of key) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return TINTS[h % TINTS.length]!;
}
export function initials(name: string) {
  const parts = name.replace(/^@/, '').split(/[\s_-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts[1]?.[0] ?? parts[0]?.[1] ?? '')).toUpperCase();
}

export function Avatar({ name, login, square, size }: { name: string; login?: string; square?: boolean; size?: 'sm' | 'lg' }) {
  const [bg, fg] = tint(name);
  const [failed, setFailed] = useState(false);
  return (
    <span className={`avatar${square ? ' square' : ''}${size ? ' ' + size : ''}`} style={{ background: bg, color: fg }} aria-hidden="true">
      {login && !failed ? <img src={`https://github.com/${encodeURIComponent(login)}.png?size=64`} alt="" onError={() => setFailed(true)} referrerPolicy="no-referrer" /> : initials(name)}
    </span>
  );
}

const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;
export const Icon = {
  logo: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" {...P} stroke="#fff" aria-hidden="true"><path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z" /></svg>
  ),
  lock: (s = 12) => (
    <svg width={s} height={s} viewBox="0 0 24 24" {...P} strokeWidth={2.4} aria-hidden="true"><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></svg>
  ),
  plus: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} strokeWidth={2.2} aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
  ),
  people: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18.5 14a6.5 6.5 0 0 1 3 6" /></svg>
  ),
  clip: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="m21 11-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7" /></svg>
  ),
  shield: (ok: boolean) => (
    <svg width="14" height="14" viewBox="0 0 24 24" {...P} strokeWidth={2.4} aria-hidden="true"><path d="M12 3 4 6v6c0 5 3.4 8.3 8 9 4.6-.7 8-4 8-9V6z" />{ok ? <path d="m9 12 2 2 4-4" /> : <path d="M12 8v4M12 16h.01" />}</svg>
  ),
  back: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="m15 18-6-6 6-6" /></svg>
  ),
  close: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M18 6 6 18M6 6l12 12" /></svg>
  ),
  gear: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></svg>
  ),
};

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    addEventListener('keydown', k);
    return () => removeEventListener('keydown', k);
  }, [onClose]);
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="btn icon" onClick={onClose} aria-label="Close">{Icon.close()}</button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function ErrorFlash({ error }: { error?: string }) {
  if (!error) return null;
  return <div className="flash error" role="alert">{error}</div>;
}

export function timeLabel(ts: number) {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const y = new Date(now);
  y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday';
  if (now.getTime() - ts < 6 * 86_400_000) return d.toLocaleDateString([], { weekday: 'short' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

/** Run an async action with busy and error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(undefined);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}
