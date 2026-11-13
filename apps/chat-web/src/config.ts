/** Deployment settings. In production the app is served by the same Worker that holds the API. */
const env = import.meta.env;

export const CONFIG = {
  /** GitHub REST API. */
  api: (env.VITE_API as string | undefined) ?? 'https://api.github.com',
  /** The chat-over-github Worker (OAuth exchange + invite inbox). Same origin in production. */
  worker: (env.VITE_WORKER as string | undefined) ?? location.origin,
  /** GitHub App "chatovergithub". The client ID is public. */
  clientId: 'Iv23liFOHVM634uq8c39',
  appSlug: 'chatovergithub',
  /** Dev/test build against the in-memory GitHub mock. */
  mock: env.VITE_MOCK === '1',
  /** Repo names: the same for every user, so they reveal nothing. */
  directoryRepo: 'keyhold-id',
  /**
   * The private "home" repo (vault + personal store). New users create it themselves before
   * installing the app, so GitHub's "Only select repositories" has something to select.
   */
  homeRepo: 'chat-home',
  /** Home repo name used before 2026-11-13; kept for accounts that already have one. */
  legacyHomeRepo: 'keyhold-home',
  chatPrefix: 'ghchat-',
};

export const installUrl = () => `https://github.com/apps/${CONFIG.appSlug}/installations/new`;
export const newHomeRepoUrl = () =>
  `https://github.com/new?${new URLSearchParams({
    name: CONFIG.homeRepo,
    visibility: 'private',
    description: 'Private home of my end-to-end encrypted chat app (encrypted settings and key backup).',
  })}`;
