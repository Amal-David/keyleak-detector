# Convex Support

KeyLeak treats Convex as a function-oriented backend, not as a table API.

## What Convex Exposes

- Web clients connect to a deployment URL such as `https://happy-animal-123.convex.cloud`. This public deployment URL is not a vulnerability or secret by itself.
- Convex functions are public and client-callable by default. Functions that clients must not call directly should use `internalQuery`, `internalMutation`, or `internalAction`.
- Queries are read-only. Mutations can write database data, and actions can call external services.
- The documented HTTP API accepts public function calls at `/api/query`, `/api/mutation`, and `/api/action`.
- The open-source JavaScript client sends query subscriptions as `ModifyQuerySet` messages containing an `Add` record with `queryId` and `udfPath`. Query results arrive in `Transition` messages as `QueryUpdated` records with the same `queryId`.

Official sources:

- [Deployment URLs](https://docs.convex.dev/client/react/deployment-urls)
- [Internal functions and public-by-default behavior](https://docs.convex.dev/functions/internal-functions)
- [Query functions](https://docs.convex.dev/functions/query-functions)
- [Functions and their read/write capabilities](https://docs.convex.dev/functions/overview)
- [HTTP API](https://docs.convex.dev/http-api/)
- [Convex JavaScript sync protocol](https://github.com/get-convex/convex-js/blob/main/src/browser/sync/protocol.ts)

## What KeyLeak Confirms

The extension recognizes default `*.convex.cloud` sync endpoints and `*.convex.site` HTTP-action endpoints. It forwards only sanitized query metadata from client WebSocket messages: an opaque connection ID, query ID, function path, and whether that socket has authenticated. It never forwards a Convex bearer token or query arguments, and it never correlates authentication or query IDs across sockets.

When an unauthenticated query later receives a `QueryUpdated` value, KeyLeak emits a confirmed `convex_anonymous_query_data` finding. A public query can be intentional, so ordinary function names are medium severity; names that indicate private, administrative, billing, credential, or token data are high severity. Empty results are low-severity observations rather than confirmed exposed data.

The default finding contains a redacted structural preview. `REVEAL RAW SAMPLE` can display up to two actual result rows held in tab-scoped service-worker memory. Each observed result has its own sample key, so a later update cannot replace the rows referenced by an earlier finding. Those rows never enter extension storage, reports, logs, clipboard exports, or native messages.

## Safety Boundary

KeyLeak does not invoke mutations or actions, does not guess function names, does not replay authenticated traffic, and does not call the Convex HTTP API. It validates only query results already observed in the browser's anonymous Convex session.

Current limitations:

- Custom/self-hosted Convex domains are not identified from the hostname alone.
- Chunked `TransitionChunk` results are not reconstructed.
- `*.convex.site` HTTP actions are detected as Convex infrastructure but are not invoked or classified for impact.
- A function returning data anonymously is confirmed behavior, but the operator must decide whether that data is intentionally public.
