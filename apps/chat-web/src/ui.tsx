import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react';
import { CONFIG } from './config';
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

export function Avatar({ name, login, square, size }: { name: string; login?: string; square?: boolean; size?: 'sm' | 'lg' | 'xl' }) {
  const [bg, fg] = tint(name);
  const [failed, setFailed] = useState(false);
  return (
    <span className={`avatar${square ? ' square' : ''}${size ? ' ' + size : ''}`} style={{ background: bg, color: fg }} aria-hidden="true">
      {login && !failed ? <img src={`https://github.com/${encodeURIComponent(login)}.png?size=96`} alt="" onError={() => setFailed(true)} referrerPolicy="no-referrer" /> : initials(name)}
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
  shield: (ok: boolean, s = 14) => (
    <svg width={s} height={s} viewBox="0 0 24 24" {...P} strokeWidth={2.4} aria-hidden="true"><path d="M12 3 4 6v6c0 5 3.4 8.3 8 9 4.6-.7 8-4 8-9V6z" />{ok ? <path d="m9 12 2 2 4-4" /> : <path d="M12 8v4M12 16h.01" />}</svg>
  ),
  more: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.9" /><circle cx="12" cy="12" r="1.9" /><circle cx="19" cy="12" r="1.9" /></svg>
  ),
  send: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} strokeWidth={2.4} aria-hidden="true"><path d="M12 19V5M5.5 11.5 12 5l6.5 6.5" /></svg>
  ),
  compose: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M12 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6" /><path d="M18.4 2.6a2 2 0 0 1 2.9 2.9L12 14.7 8 16l1.3-4z" /></svg>
  ),
  search: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" {...P} strokeWidth={2.2} aria-hidden="true"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
  ),
  info: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7.5h.01" /></svg>
  ),
  trash: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3" /></svg>
  ),
  exit: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 16l-4-4 4-4M6 12h10" /></svg>
  ),
  block: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" {...P} aria-hidden="true"><circle cx="12" cy="12" r="9" /><path d="m5.7 5.7 12.6 12.6" /></svg>
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
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
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

/** Where to put a floating box (menu or hint) next to its trigger, kept inside the window. */
function place(trigger: HTMLElement, width: number, height: number, align: 'start' | 'end') {
  const r = trigger.getBoundingClientRect();
  const left = Math.max(8, Math.min(align === 'end' ? r.right - width : r.left + r.width / 2 - width / 2, innerWidth - width - 8));
  const below = r.bottom + 6 + height <= innerHeight - 8 || r.top < height + 14;
  return { left, top: below ? r.bottom + 6 : r.top - 6 - height };
}

/** A round "?" that shows a short explanation on hover, focus or tap. Keeps the screen itself quiet. */
export function Hint({ text, children, label = 'More information', className }: { text: ReactNode; children?: ReactNode; label?: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number }>();
  const btn = useRef<HTMLButtonElement>(null);
  const pop = useRef<HTMLSpanElement>(null);
  useLayoutEffect(() => {
    if (open && btn.current && pop.current) setPos(place(btn.current, pop.current.offsetWidth, pop.current.offsetHeight, 'start'));
    else setPos(undefined);
  }, [open]);
  return (
    <span className="hint-wrap" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
      <button
        ref={btn}
        type="button"
        className={className ?? 'hint'}
        aria-label={label}
        aria-expanded={open}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(true); }}
      >
        {children ?? '?'}
      </button>
      {open && <span ref={pop} role="tooltip" className="hint-pop" style={pos ? { ...pos, visibility: 'visible' } : undefined}>{text}</span>}
    </span>
  );
}

/** A button that opens a small floating menu. `children` gets a `close` function. */
export function Menu({ label, className = 'btn icon ghost', icon, children }: { label: string; className?: string; icon?: ReactNode; children: (close: () => void) => ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number }>();
  const btn = useRef<HTMLButtonElement>(null);
  const pop = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    if (open && btn.current && pop.current) setPos(place(btn.current, pop.current.offsetWidth, pop.current.offsetHeight, 'end'));
    else setPos(undefined);
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !pop.current?.contains(e.target as Node) && !btn.current?.contains(e.target as Node)) setOpen(false);
    };
    const shut = () => setOpen(false);
    addEventListener('mousedown', away);
    addEventListener('keydown', away);
    addEventListener('resize', shut);
    return () => {
      removeEventListener('mousedown', away);
      removeEventListener('keydown', away);
      removeEventListener('resize', shut);
    };
  }, [open]);
  return (
    <>
      <button ref={btn} type="button" className={`${className}${open ? ' open' : ''}`} aria-label={label} title={label} aria-haspopup="menu" aria-expanded={open} onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}>
        {icon ?? Icon.more()}
      </button>
      {open && (
        <div ref={pop} className="menu" role="menu" aria-label={label} style={pos ? { ...pos, visibility: 'visible' } : undefined}>
          {children(() => setOpen(false))}
        </div>
      )}
    </>
  );
}

export function MenuItem({ icon, danger, disabled, onClick, children }: { icon?: ReactNode; danger?: boolean; disabled?: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" role="menuitem" className={`menu-item${danger ? ' danger' : ''}`} disabled={disabled} onClick={onClick}>
      <span className="menu-icon">{icon}</span>
      <span>{children}</span>
    </button>
  );
}

/* Confirmations and short notices, drawn by the app instead of the browser. */
export interface AskOptions { title: string; body?: string; confirm: string; danger?: boolean }
let askImpl: (o: AskOptions) => Promise<boolean> = (o) => Promise.resolve(window.confirm(o.body ? `${o.title}\n\n${o.body}` : o.title));
let toastImpl: (text: string) => void = (text) => console.warn(text);
/** Ask before doing something that can't be undone. Resolves true when the person confirms. */
export const ask = (o: AskOptions): Promise<boolean> =>
  // The local end-to-end test (mock build only) answers yes without the dialog.
  CONFIG.mock && (window as { __autoConfirm?: boolean }).__autoConfirm ? Promise.resolve(true) : askImpl(o);
export const toast = (text: string) => toastImpl(text);

export function Overlays() {
  const [req, setReq] = useState<{ o: AskOptions; done: (ok: boolean) => void }>();
  const [note, setNote] = useState<string>();
  useEffect(() => {
    askImpl = (o) => new Promise((done) => setReq({ o, done }));
    let t: ReturnType<typeof setTimeout>;
    toastImpl = (text) => {
      setNote(text);
      clearTimeout(t);
      t = setTimeout(() => setNote(undefined), 6000);
    };
    return () => clearTimeout(t);
  }, []);
  const answer = (ok: boolean) => {
    req?.done(ok);
    setReq(undefined);
  };
  return (
    <>
      {req && (
        <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && answer(false)}>
          <div className="modal confirm" role="alertdialog" aria-modal="true" aria-label={req.o.title}>
            <div className="modal-body">
              <h3>{req.o.title}</h3>
              {req.o.body && <p className="muted">{req.o.body}</p>}
              <div className="confirm-actions">
                <button className="btn" autoFocus onClick={() => answer(false)}>Cancel</button>
                <button className={`btn ${req.o.danger ? 'danger solid' : 'primary'}`} onClick={() => answer(true)}>{req.o.confirm}</button>
              </div>
            </div>
          </div>
        </div>
      )}
      {note && <div className="toast" role="status" onClick={() => setNote(undefined)}>{note}</div>}
    </>
  );
}
