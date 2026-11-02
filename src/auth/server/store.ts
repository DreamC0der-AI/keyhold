/**
 * Short-lived server state for email codes and seed challenges.
 * Implement `TokenStore` over whatever you have (D1, KV, Redis, SQL). Two are included.
 */
export interface TokenStore {
  put(key: string, value: string, expiresAt: number): Promise<void>;
  get(key: string): Promise<string | undefined>;
  /** Read and delete in one step (single use). */
  take(key: string): Promise<string | undefined>;
  delete(key: string): Promise<void>;
}

export class MemoryTokenStore implements TokenStore {
  private map = new Map<string, { value: string; expiresAt: number }>();
  constructor(private readonly now: () => number = Date.now) {}
  async put(key: string, value: string, expiresAt: number) {
    this.map.set(key, { value, expiresAt });
  }
  async get(key: string) {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (e.expiresAt <= this.now()) {
      this.map.delete(key);
      return undefined;
    }
    return e.value;
  }
  async take(key: string) {
    const v = await this.get(key);
    this.map.delete(key);
    return v;
  }
  async delete(key: string) {
    this.map.delete(key);
  }
}

/** The subset of Cloudflare D1's API this store uses (so there is no hard dependency). */
export interface D1Like {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      first<T = Record<string, unknown>>(): Promise<T | null>;
      run(): Promise<unknown>;
    };
  };
}

/** SQL for D1TokenStore. Add it to your migrations. */
export const D1_TOKEN_TABLE_SQL = `CREATE TABLE IF NOT EXISTS keyhold_tokens (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS keyhold_tokens_expires ON keyhold_tokens (expires_at);`;

export class D1TokenStore implements TokenStore {
  constructor(
    private readonly db: D1Like,
    private readonly table = 'keyhold_tokens',
    private readonly now: () => number = Date.now,
  ) {}
  async put(key: string, value: string, expiresAt: number) {
    await this.db
      .prepare(`INSERT INTO ${this.table} (key, value, expires_at) VALUES (?1, ?2, ?3)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`)
      .bind(key, value, expiresAt)
      .run();
  }
  async get(key: string) {
    const row = await this.db
      .prepare(`SELECT value FROM ${this.table} WHERE key = ?1 AND expires_at > ?2`)
      .bind(key, this.now())
      .first<{ value: string }>();
    return row?.value;
  }
  async take(key: string) {
    const row = await this.db
      .prepare(`DELETE FROM ${this.table} WHERE key = ?1 RETURNING value, expires_at`)
      .bind(key)
      .first<{ value: string; expires_at: number }>();
    return row && row.expires_at > this.now() ? row.value : undefined;
  }
  async delete(key: string) {
    await this.db.prepare(`DELETE FROM ${this.table} WHERE key = ?1`).bind(key).run();
  }
  /** Call from a cron trigger to drop expired rows. */
  async purgeExpired() {
    await this.db.prepare(`DELETE FROM ${this.table} WHERE expires_at <= ?1`).bind(this.now()).run();
  }
}
