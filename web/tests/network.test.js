import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NetworkAcquisitionError,
  normalizePublicHttpsUrl,
  fetchPublicResource,
  discoverSubdomains,
} from '../src/network.js';

const textResponse = (content, headers = {}) => new Response(content, {
  headers: { 'content-type': 'text/plain; charset=utf-8', ...headers },
});
const jsonResponse = (data) => new Response(JSON.stringify(data), {
  headers: { 'content-type': 'application/json' },
});
const codeIs = (code) => (error) => error instanceof NetworkAcquisitionError && error.code === code;

test('public HTTPS normalization is canonical and strips fragments', () => {
  assert.equal(normalizePublicHttpsUrl('https://EXAMPLE.com:443/app.js?v=1#ignored').href, 'https://example.com/app.js?v=1');
  assert.equal(normalizePublicHttpsUrl('https://example.com:8443/file').port, '8443');
  assert.equal(normalizePublicHttpsUrl('https://8.8.8.8/').hostname, '8.8.8.8');
  assert.equal(normalizePublicHttpsUrl('https://[2606:4700:4700::1111]/').hostname, '[2606:4700:4700::1111]');
  assert.equal(normalizePublicHttpsUrl('https://public.internal.example.com/').hostname, 'public.internal.example.com');
});

test('network acquisition rejects internal, metadata, reserved, and disguised literal hosts', () => {
  const blocked = [
    '127.0.0.1', '127.1', '2130706433', '0x7f000001', '0177.0.0.1', '%31%32%37.0.0.1',
    '127.0.0.1.', '0.0.0.0', '10.1.2.3', '172.16.1.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '100.100.100.200', '168.63.129.16',
    '192.0.0.1', '192.0.2.1', '192.88.99.1', '198.18.0.1', '198.19.1.1',
    '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    'localhost', 'localhost.', 'a.localhost', 'printer.local', 'router.home.arpa',
    'metadata.google.internal', 'metadata.goog', 'instance-data', 'server',
    'a.test', 'a.invalid', 'a.onion', 'a.example',
    '[::]', '[::1]', '[::ffff:127.0.0.1]', '[::ffff:a9fe:a9fe]',
    '[::ffff:0:127.0.0.1]', '[64:ff9b::a9fe:a9fe]', '[fe80::1]', '[febf::1]',
    '[fc00::1]', '[fdff::1]', '[fec0::1]', '[ff02::1]',
    '[2001:db8::1]', '[2001::1]', '[2002:7f00:1::1]', '[3fff::1]',
  ];
  for (const host of blocked) {
    assert.throws(() => normalizePublicHttpsUrl(`https://${host}/`), codeIs('BLOCKED_HOST'), host);
  }
});

test('userinfo, unsupported protocols, and ambiguous syntax fail before fetch', async () => {
  const urls = [
    'https://user:secret@example.com/', 'https://@example.com/',
    'http://example.com/', 'file:///etc/passwd', 'data:text/plain,hello',
    'https://example.com\\@127.0.0.1/', 'https://exa\nmple.com/',
    'https://example.com/has space', 'https:example.com',
  ];
  for (const url of urls) {
    let called = false;
    await assert.rejects(fetchPublicResource(url, { fetchImpl: () => { called = true; } }), NetworkAcquisitionError);
    assert.equal(called, false, url);
  }
});

test('one resource fetch omits credentials/referrer, refuses redirects, and keeps queries out of provenance', async () => {
  const calls = [];
  const resource = await fetchPublicResource('https://example.com/app.js?token=private-value#anchor', {
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return textResponse('const value = "local";', { 'content-type': 'application/javascript' });
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://example.com/app.js?token=private-value');
  assert.equal(calls[0].options.credentials, 'omit');
  assert.equal(calls[0].options.referrerPolicy, 'no-referrer');
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.mode, 'cors');
  assert.equal(calls[0].options.cache, 'no-store');
  assert.deepEqual(Object.keys(calls[0].options.headers), ['Accept']);
  assert.deepEqual(resource, {
    name: 'example.com/app.js', content: 'const value = "local";',
    type: 'application/javascript', sourceUrl: 'https://example.com/app.js',
  });
});

test('opaque and error responses are explicit incomplete acquisitions', async () => {
  for (const type of ['opaque', 'opaqueredirect', 'error']) {
    await assert.rejects(fetchPublicResource('https://example.com/', {
      fetchImpl: async () => ({ type }),
    }), codeIs('UNREADABLE_RESPONSE'));
  }
  await assert.rejects(fetchPublicResource('https://example.com/', {
    fetchImpl: async () => new Response('missing', { status: 404 }),
  }), codeIs('HTTP_ERROR'));
  await assert.rejects(fetchPublicResource('https://example.com/', {
    fetchImpl: async () => ({ type: 'cors', redirected: true }),
  }), codeIs('REDIRECT_BLOCKED'));
});

test('network failures do not leak URL tokens or claim the resource is clean', async () => {
  await assert.rejects(fetchPublicResource('https://example.com/?key=secret-query-value', {
    fetchImpl: async () => { throw new Error('CORS failed on secret-query-value'); },
  }), (error) => {
    assert.equal(error.code, 'NETWORK_OR_CORS');
    assert.match(error.message, /has not been scanned/);
    assert.doesNotMatch(error.message, /secret-query-value/);
    assert.equal(error.cause, undefined);
    return true;
  });
});

test('missing/binary MIME types are rejected and their bodies are cancelled', async () => {
  for (const contentType of ['', 'image/png', 'application/octet-stream']) {
    let cancelled = false;
    const body = new ReadableStream({ cancel() { cancelled = true; } });
    const headers = contentType ? { 'content-type': contentType } : {};
    await assert.rejects(fetchPublicResource('https://example.com/file', {
      fetchImpl: async () => new Response(body, { headers }),
    }), codeIs('UNSUPPORTED_CONTENT_TYPE'));
    assert.equal(cancelled, true);
  }
});

test('declared oversize and decoded streaming oversize both stop acquisition', async () => {
  let declaredCancelled = false;
  await assert.rejects(fetchPublicResource('https://example.com/large', {
    maxBytes: 4,
    fetchImpl: async () => new Response(new ReadableStream({ cancel() { declaredCancelled = true; } }), {
      headers: { 'content-type': 'text/plain', 'content-length': '5' },
    }),
  }), codeIs('RESOURCE_TOO_LARGE'));
  assert.equal(declaredCancelled, true);

  let streamCancelled = false;
  let requestSignal;
  await assert.rejects(fetchPublicResource('https://example.com/chunked', {
    maxBytes: 4,
    fetchImpl: async (_url, options) => {
      requestSignal = options.signal;
      return new Response(new ReadableStream({
        start(controller) { controller.enqueue(new TextEncoder().encode('12345')); },
        cancel() { streamCancelled = true; },
      }), { headers: { 'content-type': 'text/plain', 'content-length': '1' } });
    },
  }), codeIs('RESOURCE_TOO_LARGE'));
  assert.equal(streamCancelled, true);
  assert.equal(requestSignal.aborted, true);
});

test('streamed UTF-8 uses byte limits and decodes split multibyte characters', async () => {
  const bytes = new TextEncoder().encode('a€b');
  const makeResponse = () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice(0, 2));
      controller.enqueue(bytes.slice(2, 4));
      controller.enqueue(bytes.slice(4));
      controller.close();
    },
  }), { headers: { 'content-type': 'text/plain' } });
  const result = await fetchPublicResource('https://example.com/utf8', { maxBytes: 5, fetchImpl: async () => makeResponse() });
  assert.equal(result.content, 'a€b');
  await assert.rejects(fetchPublicResource('https://example.com/utf8', { maxBytes: 4, fetchImpl: async () => makeResponse() }), codeIs('RESOURCE_TOO_LARGE'));
});

test('request timeouts are bounded even if a fetch implementation never settles', async () => {
  let signal;
  await assert.rejects(fetchPublicResource('https://example.com/stalled', {
    timeoutMs: 5,
    fetchImpl: (_url, options) => { signal = options.signal; return new Promise(() => {}); },
  }), codeIs('TIMEOUT'));
  assert.equal(signal.aborted, true);
});

test('cancellation stops stalled body reads and pre-aborted operations never fetch', async () => {
  const controller = new AbortController();
  let cancelled = false;
  const operation = fetchPublicResource('https://example.com/stalled-body', {
    signal: controller.signal,
    fetchImpl: async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), {
      headers: { 'content-type': 'text/plain' },
    }),
  });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(operation, codeIs('ABORTED'));
  assert.equal(cancelled, true);
  let called = false;
  await assert.rejects(fetchPublicResource('https://example.com/', {
    signal: controller.signal, fetchImpl: () => { called = true; },
  }), codeIs('ABORTED'));
  assert.equal(called, false);
});

test('resource limits cannot be disabled or raised above hard caps', async () => {
  for (const options of [{ maxBytes: 0 }, { maxBytes: Infinity }, { maxBytes: 11 * 1024 * 1024 }, { timeoutMs: 60001 }]) {
    await assert.rejects(fetchPublicResource('https://example.com/', {
      ...options, fetchImpl: () => assert.fail('must not fetch'),
    }), codeIs('INVALID_OPTIONS'));
  }
});

test('bounded DNS discovery uses only the fixed resolver and returns scoped A/AAAA/CNAME evidence', async () => {
  const calls = [];
  let active = 0;
  let peak = 0;
  const result = await discoverSubdomains('EXAMPLE.com.', {
    maxCandidates: 2,
    concurrency: 2,
    fetchImpl: async (rawUrl, options) => {
      const url = new URL(rawUrl);
      calls.push(url);
      assert.equal(url.origin, 'https://dns.google');
      assert.equal(url.pathname, '/resolve');
      assert.equal(url.searchParams.get('edns_client_subnet'), '0.0.0.0/0');
      assert.equal(options.credentials, 'omit');
      const hostname = url.searchParams.get('name');
      assert.ok(hostname.endsWith('.example.com'));
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      if (hostname.startsWith('kl-')) return jsonResponse({ Status: 3 });
      const type = url.searchParams.get('type');
      if (hostname.startsWith('www.')) return jsonResponse({ Status: 0, Answer: [{
        name: `${hostname}.`, type: type === 'A' ? 1 : 28,
        data: type === 'A' ? '8.8.8.8' : '2606:4700:4700::1111',
      }] });
      return jsonResponse({ Status: 0, Answer: [
        { name: hostname, type: 5, data: 'outside.provider.net.' },
        { name: 'outside.provider.net.', type: 1, data: '8.8.4.4' },
        { name: 'unrelated.example.net.', type: 1, data: '9.9.9.9' },
      ] });
    },
  });
  assert.equal(result.domain, 'example.com');
  assert.equal(result.resolver, 'google');
  assert.equal(result.complete, true);
  assert.equal(result.wildcardStatus, 'not-detected');
  assert.equal(result.wildcardDetected, false);
  assert.equal(result.stats.requests, 8);
  assert.equal(result.stats.candidatesChecked, 2);
  assert.equal(peak, 2);
  assert.deepEqual(result.subdomains.map((item) => item.hostname), ['www.example.com', 'api.example.com']);
  assert.deepEqual(result.subdomains[0].addresses, ['8.8.8.8', '2606:4700:4700::1111']);
  assert.deepEqual(result.subdomains[1].addresses, ['8.8.4.4']);
  assert.ok(result.subdomains[1].recordTypes.includes('CNAME'));
  assert.equal(calls.length, 8);
  assert.match(result.notice, /Google receives/);
  assert.match(result.notice, /No discovered website was fetched/);
});

test('wildcard DNS marks results ambiguous rather than asserting independent hosts', async () => {
  const result = await discoverSubdomains('example.com', {
    maxCandidates: 1,
    fetchImpl: async (rawUrl) => {
      const hostname = new URL(rawUrl).searchParams.get('name');
      return jsonResponse({ Status: 0, Answer: [{ name: hostname, type: 1, data: '8.8.8.8' }] });
    },
  });
  assert.equal(result.wildcardDetected, true);
  assert.equal(result.wildcardStatus, 'detected');
  assert.equal(result.subdomains[0].wildcardSuspected, true);
});

test('DNS failures are preserved and wildcard failures make detection inconclusive', async () => {
  const result = await discoverSubdomains('example.com', {
    maxCandidates: 1,
    fetchImpl: async () => jsonResponse({ Status: 2 }),
  });
  assert.equal(result.complete, false);
  assert.equal(result.wildcardStatus, 'inconclusive');
  assert.equal(result.errors.length, 6);
  assert.ok(result.errors.every((error) => error.code === 'DNS_ERROR'));
  assert.deepEqual(result.subdomains, []);
});

test('truncated/malformed DNS answers cannot count as complete discovery', async () => {
  for (const payload of [
    { Status: 0, TC: true }, { Answer: [] }, { Status: 0, Answer: 'bad' },
    { Status: 0, Answer: [{ type: 1, data: '8.8.8.8' }] },
    { Status: 0, Answer: [{ name: 'www.example.com', type: 1, data: 'not-an-ip' }] },
  ]) {
    const result = await discoverSubdomains('example.com', { maxCandidates: 1, fetchImpl: async () => jsonResponse(payload) });
    assert.equal(result.complete, false);
    assert.ok(result.errors.length > 0);
    assert.deepEqual(result.subdomains, []);
  }
});

test('DNS total timeout and cancellation stop the queue without target requests', async () => {
  let calls = 0;
  await assert.rejects(discoverSubdomains('example.com', {
    totalTimeoutMs: 5,
    timeoutMs: 100,
    fetchImpl: () => { calls += 1; return new Promise(() => {}); },
  }), codeIs('DISCOVERY_TIMEOUT'));
  assert.equal(calls, 2);
  const controller = new AbortController();
  const operation = discoverSubdomains('example.com', {
    signal: controller.signal,
    fetchImpl: () => new Promise(() => {}),
  });
  setTimeout(() => controller.abort(), 5);
  await assert.rejects(operation, codeIs('ABORTED'));
});

test('DNS discovery caps enumeration to 36 requests and rejects custom endpoints or malformed domains', async () => {
  let calls = 0;
  const result = await discoverSubdomains('example.com', {
    maxCandidates: 16, concurrency: 4,
    fetchImpl: async () => { calls += 1; return jsonResponse({ Status: 3 }); },
  });
  assert.equal(calls, 36);
  assert.equal(result.stats.requests, 36);
  assert.equal(result.subdomains.length, 0);
  for (const options of [{ resolver: 'https://proxy.invalid/' }, { maxCandidates: 17 }, { concurrency: 5 }]) {
    await assert.rejects(discoverSubdomains('example.com', {
      ...options, fetchImpl: () => assert.fail('must not fetch'),
    }), NetworkAcquisitionError);
  }
  for (const domain of ['https://example.com/', 'user@example.com', 'example.com/path', 'example.com:443', '127.0.0.1', 'localhost', 'evil.local']) {
    await assert.rejects(discoverSubdomains(domain, { fetchImpl: () => assert.fail('must not fetch') }), NetworkAcquisitionError);
  }
});
