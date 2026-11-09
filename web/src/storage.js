const MAX_REPORTS = 50;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const PRIVATE_KEYS = new Set(['raw_value', 'raw_sample_rows', 'rawSampleRows', 'content', 'body', 'bytes', 'inputs']);

// Only reports pass through this boundary. File contents and acquired responses
// belong to the worker lifetime and are never part of the persistence contract.
export function reportSnapshot(report) {
  const encoded = JSON.stringify(report, (key, value) => PRIVATE_KEYS.has(key) ? undefined : value);
  if (!encoded || encoded.length > MAX_REPORT_BYTES) throw new Error('The report is too large to save locally. Export it instead.');
  const safe = JSON.parse(encoded);
  if (!Array.isArray(safe.findings) || !safe.coverage || !safe.verdict) throw new Error('Invalid report.');
  return safe;
}

export function storageName(base = new URL('../', import.meta.url)) {
  return `keyleak-browser-v1:${base.pathname}`;
}

export async function openReportStore(indexedDB = globalThis.indexedDB, name = storageName()) {
  if (!indexedDB) throw new Error('Local history is unavailable in this browser. Reports can still be exported.');
  const db = await new Promise((resolve, reject) => {
    let request;
    let settled = false;
    const fail = message => { if (!settled) { settled = true; reject(new Error(message)); } };
    try { request = indexedDB.open(name, 1); } catch (_) { reject(new Error('Local history is unavailable.')); return; }
    request.onupgradeneeded = () => request.result.createObjectStore('reports', { keyPath: 'id' });
    request.onsuccess = () => { if (settled) request.result.close(); else { settled = true; resolve(request.result); } };
    request.onerror = () => fail('Local history is unavailable. Reports can still be exported.');
    request.onblocked = () => fail('Close other KeyLeak tabs to open local history.');
  });
  db.onversionchange = () => db.close();

  function transact(mode, operation) {
    return new Promise((resolve, reject) => {
      let result;
      let transaction;
      try {
        transaction = db.transaction('reports', mode);
        const request = operation(transaction.objectStore('reports'));
        request.onsuccess = () => { result = request.result; };
      } catch (_) { reject(new Error('Local history could not be accessed. Export this report to keep a copy.')); return; }
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(new Error('Local history could not be saved. Storage may be full; export this report.'));
      transaction.onabort = () => reject(new Error('Local history operation was interrupted.'));
    });
  }

  return {
    async list() {
      const records = await transact('readonly', store => store.getAll());
      return records.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },
    async save(report) {
      const safe = reportSnapshot(report);
      const createdAt = new Date().toISOString();
      const id = globalThis.crypto.randomUUID();
      await transact('readwrite', store => store.put({ id, createdAt, report: safe }));
      const records = await this.list();
      for (const record of records.slice(MAX_REPORTS)) await this.remove(record.id);
      return id;
    },
    remove(id) { return transact('readwrite', store => store.delete(id)); },
    clear() { return transact('readwrite', store => store.clear()); },
    close() { db.close(); },
  };
}
