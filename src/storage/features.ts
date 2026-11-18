/**
 * Build options and feature resolution: a product chooses options when it builds with
 * keyhold; the provider declares capabilities; features are on only when both agree.
 */
import { KeyholdError } from '../util/errors.js';
import type { Capability, StorageProvider } from './interfaces.js';

export interface BuildOptions {
  /**
   * Box 4: let members add someone who is offline, using one-time KeyPackages from a
   * claim-once store. Off by default: people join when they accept (external join).
   */
  offlineAdd?: boolean;
  /** Allow the weaker reusable last-resort KeyPackage from the directory when box 4 is empty. */
  lastResortKeyPackages?: boolean;
  /** Back up decrypted message history to the personal synced store (box 12). Default on. */
  historyBackup?: boolean;
}

export interface Features {
  offlineAdd: boolean;
  lastResortKeyPackages: boolean;
  historyBackup: boolean;
  /** Notices can carry a payload; else they only point at the channel grant. */
  inboxPayload: boolean;
  /** Only the space creator can change channel access, so other admins rely on the creator's app. */
  ownerManagedSpaces: boolean;
}

const REQUIRES: Partial<Record<keyof BuildOptions, Capability>> = { offlineAdd: 'claim-once' };

/**
 * Resolve features. With `strict`, asking for an option the provider can't support throws
 * instead of silently turning it off.
 */
export function resolveFeatures(provider: Pick<StorageProvider, 'capabilities' | 'claimOnce' | 'name'>, options: BuildOptions = {}, strict = false): Features {
  const has = (c: Capability) => provider.capabilities.has(c);
  for (const [opt, cap] of Object.entries(REQUIRES) as [keyof BuildOptions, Capability][]) {
    if (options[opt] && !has(cap) && strict) {
      throw new KeyholdError('unsupported', `${opt} needs the ${cap} capability, which provider ${provider.name} lacks`);
    }
  }
  return {
    offlineAdd: !!options.offlineAdd && has('claim-once') && !!provider.claimOnce,
    lastResortKeyPackages: !!options.lastResortKeyPackages,
    historyBackup: options.historyBackup ?? true,
    inboxPayload: has('inbox-payload'),
    ownerManagedSpaces: has('owner-managed-spaces'),
  };
}
