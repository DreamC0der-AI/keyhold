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
  homeRepo: 'keyhold-home',
  chatPrefix: 'ghchat-',
};

export const installUrl = () => `https://github.com/apps/${CONFIG.appSlug}/installations/new`;
