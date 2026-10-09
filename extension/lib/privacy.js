export function normalizeOrigin(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
  } catch (_error) {
    return '';
  }
}

export function shouldRunPrivacyMigration(storedVersion, currentVersion) {
  return storedVersion !== currentVersion;
}

export function isOriginPaused(pageUrl, pausedOrigins = []) {
  const origin = normalizeOrigin(pageUrl);
  const includes = pausedOrigins instanceof Set
    ? pausedOrigins.has(origin)
    : pausedOrigins.includes(origin);
  return Boolean(origin && includes);
}

export function isPagePaused(ownerUrl, topLevelUrl, pausedOrigins = []) {
  return isOriginPaused(ownerUrl, pausedOrigins) || isOriginPaused(topLevelUrl, pausedOrigins);
}

export class ActivityEpochs {
  #epochs = new Map();

  current(tabId) {
    return this.#epochs.get(tabId) || 0;
  }

  advance(tabId) {
    const next = this.current(tabId) + 1;
    this.#epochs.set(tabId, next);
    return next;
  }

  clear(tabId) {
    this.#epochs.delete(tabId);
  }
}
