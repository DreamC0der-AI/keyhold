/** Minimal GitHub REST client: injected fetch, user access token, JSON in and out. */
import { KeyholdError } from '../../util/errors.js';

export type FetchFn = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => Promise<{
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export interface GitHubClientOptions {
  fetch: FetchFn;
  token: string;
  apiBase?: string;
  userAgent?: string;
}

export class GitHubClient {
  readonly base: string;
  /** Requests made, for rate-limit budgeting and tests. */
  requests = 0;
  constructor(private o: GitHubClientOptions) {
    this.base = (o.apiBase ?? 'https://api.github.com').replace(/\/$/, '');
  }

  async call(method: string, path: string, body?: unknown, accept = 'application/vnd.github+json'): Promise<{ status: number; data: any }> {
    this.requests++;
    const res = await this.o.fetch(this.base + path, {
      method,
      headers: {
        Accept: accept,
        Authorization: `Bearer ${this.o.token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        ...(this.o.userAgent ? { 'User-Agent': this.o.userAgent } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0') {
      throw new KeyholdError('too_many_attempts', 'GitHub rate limit reached; try again later');
    }
    if (res.status === 401) throw new KeyholdError('auth_failed', 'GitHub token is not valid');
    const text = await res.text();
    let data: any = undefined;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    return { status: res.status, data };
  }

  /** Throws for anything outside `ok`. */
  async expect(method: string, path: string, ok: number[], body?: unknown) {
    const r = await this.call(method, path, body);
    if (!ok.includes(r.status)) {
      const code = r.status === 403 ? 'forbidden' : r.status === 404 ? 'not_found' : r.status === 409 || r.status === 422 ? 'conflict' : 'config';
      throw new KeyholdError(code, `GitHub ${method} ${path} -> ${r.status} ${typeof r.data === 'object' ? r.data?.message ?? '' : ''}`);
    }
    return r;
  }
}
