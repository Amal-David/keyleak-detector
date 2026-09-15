import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ConvexTabState,
  parseConvexDeployment,
} from '../lib/convex-detector.js';
import { buildReport } from '../lib/reporting.js';

const SYNC_URL = 'wss://happy-animal-123.convex.cloud/api/1.31.0/sync';

test('recognizes official Convex cloud and site deployment hosts only', () => {
  assert.deepEqual(parseConvexDeployment(SYNC_URL), {
    provider: 'convex',
    deploymentUrl: 'https://happy-animal-123.convex.cloud',
    surface: 'sync',
  });
  assert.equal(
    parseConvexDeployment('https://happy-animal-123.convex.site/webhook').surface,
    'http-actions',
  );
  assert.equal(
    parseConvexDeployment('https://happy-animal-123.convex.cloud/api/query').surface,
    'functions-api',
  );
  assert.equal(parseConvexDeployment('https://convex.cloud.evil.example/api/sync'), null);
  assert.equal(parseConvexDeployment('https://notconvex.cloud/api/sync'), null);
  assert.equal(parseConvexDeployment('wss://happy-animal-123.convex.site/api/1.0/sync'), null);
});

test('confirms an observed anonymous query result without replaying a request', () => {
  const state = new ConvexTabState();
  state.observeClientMessage(SYNC_URL, JSON.stringify({
    type: 'ModifyQuerySet',
    authenticated: false,
    modifications: [{ type: 'Add', queryId: 7, udfPath: 'messages:list' }],
  }));

  const rows = [
    { _id: 'message-1', body: 'Actual first Convex row' },
    { _id: 'message-2', body: 'Actual second Convex row' },
    { _id: 'message-3', body: 'Must not be retained' },
  ];
  const findings = state.observeServerMessage(SYNC_URL, JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 7, value: rows }],
  }));

  assert.equal(findings.length, 1);
  assert.equal(findings[0].type, 'convex_anonymous_query_data');
  assert.equal(findings[0].validation_status, 'confirmed');
  assert.equal(findings[0].evidence.raw_sample_available, true);
  assert.match(findings[0].evidence.sample, /"body"/);
  assert.match(findings[0].evidence.sample, /Actu…/);
  assert.doesNotMatch(findings[0].evidence.sample, /Actual first Convex row/);
  assert.deepEqual(
    state.getRawSample('convex-query:happy-animal-123.convex.cloud/messages:list'),
    rows.slice(0, 2),
  );

  const serialized = JSON.stringify(buildReport('https://app.example', findings));
  assert.doesNotMatch(serialized, /Actual first Convex row|Actual second Convex row|message-1/);
});

test('query ids and raw samples stay isolated across Convex deployments', () => {
  const state = new ConvexTabState();
  const secondUrl = 'wss://calm-otter-456.convex.cloud/api/1.31.0/sync';
  state.observeClientMessage(SYNC_URL, JSON.stringify({
    type: 'ModifyQuerySet', authenticated: false,
    modifications: [{ type: 'Add', queryId: 1, udfPath: 'messages:list' }],
  }));
  state.observeClientMessage(secondUrl, JSON.stringify({
    type: 'ModifyQuerySet', authenticated: false,
    modifications: [{ type: 'Add', queryId: 1, udfPath: 'posts:list' }],
  }));

  const findings = state.observeServerMessage(SYNC_URL, JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 1, value: [{ body: 'first deployment' }] }],
  }));

  assert.equal(findings[0].evidence.redacted_value, 'convex-query:happy-animal-123.convex.cloud/messages:list');
  assert.equal(
    state.getRawSample('convex-query:calm-otter-456.convex.cloud/posts:list'),
    null,
  );

  state.observeServerMessage(secondUrl, JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 1, value: [{ body: 'second deployment' }] }],
  }));
  state.observeClientMessage(SYNC_URL, JSON.stringify({ type: 'Authenticate', authenticated: true }));
  assert.equal(
    state.getRawSample('convex-query:happy-animal-123.convex.cloud/messages:list'),
    null,
  );
  assert.deepEqual(
    state.getRawSample('convex-query:calm-otter-456.convex.cloud/posts:list'),
    [{ body: 'second deployment' }],
  );
});

test('authenticated, mutation, action, and guessed traffic never becomes an anonymous query finding', () => {
  const state = new ConvexTabState();
  state.observeClientMessage(SYNC_URL, JSON.stringify({
    type: 'ModifyQuerySet', authenticated: false,
    modifications: [{ type: 'Add', queryId: 1, udfPath: 'private:getProfile' }],
  }));
  state.observeClientMessage(SYNC_URL, JSON.stringify({ type: 'Authenticate', authenticated: true }));

  const transition = JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 1, value: [{ secret: 'private' }] }],
  });
  assert.deepEqual(state.observeServerMessage(SYNC_URL, transition), []);
  assert.deepEqual(state.observeClientMessage(SYNC_URL, JSON.stringify({ type: 'Mutation' })), []);
  assert.deepEqual(state.observeClientMessage(SYNC_URL, JSON.stringify({ type: 'Action' })), []);
});

test('an empty anonymous query is an observation, not confirmed exposed data', () => {
  const state = new ConvexTabState();
  state.observeClientMessage(SYNC_URL, JSON.stringify({
    type: 'ModifyQuerySet', authenticated: false,
    modifications: [{ type: 'Add', queryId: 2, udfPath: 'posts:list' }],
  }));
  const findings = state.observeServerMessage(SYNC_URL, JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 2, value: [] }],
  }));

  assert.equal(findings[0].type, 'convex_anonymous_query_empty');
  assert.equal(findings[0].severity, 'low');
  assert.equal(findings[0].validation_status, 'lead');
  assert.equal(findings[0].evidence.raw_sample_available, undefined);
});

test('oversized query data stays confirmed even when raw reveal is unavailable', () => {
  const state = new ConvexTabState();
  state.observeClientMessage(SYNC_URL, JSON.stringify({
    type: 'ModifyQuerySet', authenticated: false,
    modifications: [{ type: 'Add', queryId: 3, udfPath: 'documents:list' }],
  }));
  const findings = state.observeServerMessage(SYNC_URL, JSON.stringify({
    type: 'Transition',
    modifications: [{ type: 'QueryUpdated', queryId: 3, value: [{ body: 'x'.repeat(20_000) }] }],
  }));

  assert.equal(findings[0].type, 'convex_anonymous_query_data');
  assert.equal(findings[0].validation_status, 'confirmed');
  assert.equal(findings[0].evidence.raw_sample_available, undefined);
  assert.equal(
    state.getRawSample('convex-query:happy-animal-123.convex.cloud/documents:list'),
    null,
  );
});
