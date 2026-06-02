# Catalog → detector mapping (DRAFT, refined per milestone)

Shape: A=passive pattern (Detector), B=active probe (ActiveCheck), C=auth-differential, D=config-extract+probe. Milestones per integration-plan.md.

| # | vuln | pack | shape | milestone | draft detector id |
|---|------|------|-------|-----------|-------------------|
| 1 | idor-bola | access-control | C auth-diff | M4 | `access-control.idor-bola` |
| 2 | exposed-env-file | leak | A passive-pattern | M2 | `leak.exposed-env-file` |
| 3 | supabase-rls-open-table | baas | D config+probe | M5 | `baas.supabase-rls-open-table` |
| 4 | env-secrets-in-js-bundle | leak | A passive-pattern | M2 | `leak.env-secrets-in-js-bundle` |
| 5 | supabase-service-role-key-exposed | leak | A passive-pattern | M2 | `leak.supabase-service-role-key-exposed` |
| 6 | baas-config-exposed | baas | D config+probe | M5 | `baas.baas-config-exposed` |
| 7 | unauthenticated-api-access | access-control | C auth-diff | M4 | `access-control.unauthenticated-api-access` |
| 8 | exposed-source-maps | leak | A passive-pattern | M2 | `leak.exposed-source-maps` |
| 9 | subdomain-takeover | recon | B active-probe | M3 | `recon.subdomain-takeover` |
| 10 | default-credentials | authn | B active-probe | M3 | `authn.default-credentials` |
| 11 | token-in-webstorage | client | A passive-pattern | M2 | `client.token-in-webstorage` |
| 12 | secret-in-dom | leak | A passive-pattern | M2 | `leak.secret-in-dom` |
| 13 | debug-endpoint-exposure | recon | B active-probe | M3 | `recon.debug-endpoint-exposure` |
| 14 | spring-actuator-exposed | recon | B active-probe | M3 | `recon.spring-actuator-exposed` |
| 15 | sqli | injection | B active-probe | M7 | `injection.sqli` |
| 16 | ssrf | injection | B active-probe | M7 | `injection.ssrf` |
| 17 | nosql-injection | injection | B active-probe | M7 | `injection.nosql-injection` |
| 18 | jwt-flaw | authn | B active-probe | M3 | `authn.jwt-flaw` |
| 19 | cors-misconfig | headers | A passive-pattern | M2 | `headers.cors-misconfig` |
| 20 | mass-assignment | injection | B active-probe | M7 | `injection.mass-assignment` |
| 21 | bfla | access-control | C auth-diff | M4 | `access-control.bfla` |
| 22 | nextjs-middleware-authz-bypass | access-control | C auth-diff | M4 | `access-control.nextjs-middleware-authz-bypass` |
| 23 | path-traversal | injection | B active-probe | M7 | `injection.path-traversal` |
| 24 | ssti | injection | B active-probe | M7 | `injection.ssti` |
| 25 | open-redirect | injection | B active-probe | M7 | `injection.open-redirect` |
| 26 | h2-console-exposed | recon | B active-probe | M3 | `recon.h2-console-exposed` |
| 27 | otp-in-response | authn | A passive-pattern | M2 | `authn.otp-in-response` |
| 28 | secret-in-response-body | leak | A passive-pattern | M2 | `leak.secret-in-response-body` |
| 29 | spring-data-rest-exposure | recon | B active-probe | M3 | `recon.spring-data-rest-exposure` |
| 30 | directory-listing | recon | B active-probe | M3 | `recon.directory-listing` |
| 31 | xss-reflected-stored-dom | appsec | B active-probe | M3 | `appsec.xss-reflected-stored-dom` |
| 32 | excessive-data-exposure | api | A passive-pattern | M2 | `api.excessive-data-exposure` |
| 33 | weak-session-secret | authn | B active-probe | M3 | `authn.weak-session-secret` |
| 34 | open-cloud-storage-bucket | baas | D config+probe | M5 | `baas.baas-config-exposed-storage` |
| 35 | client-side-only-authz | access-control | C auth-diff | M4 | `access-control.client-side-only-authz` |
| 36 | graphql-introspection-exposed | api | B active-probe | M3 | `api.graphql-introspection-exposed` |
| 37 | insecure-cookie-flags | headers | A passive-pattern | M2 | `headers.insecure-cookie-flags` |
| 38 | laravel-debugbar-telescope-exposed | recon | B active-probe | M3 | `recon.laravel-debugbar-telescope-exposed` |
| 39 | go-pprof-debug-exposed | recon | B active-probe | M3 | `recon.go-pprof-debug-exposed` |
| 40 | host-header-injection | appsec | B active-probe | M3 | `appsec.host-header-injection` |
| 41 | cmd-injection | injection | B active-probe | M7 | `injection.cmd-injection` |
| 42 | resource-id-enumeration | api | B active-probe | M3 | `api.resource-id-enumeration` |
| 43 | xxe-injection | injection | B active-probe | M7 | `injection.xxe-injection` |
| 44 | token-in-query-string | leak | A passive-pattern | M2 | `leak.token-in-query-string` |
| 45 | prototype-pollution | injection | B active-probe | M7 | `injection.prototype-pollution` |
| 46 | django-admin-exposed | recon | B active-probe | M3 | `recon.django-admin-exposed` |
| 47 | rate-limit-missing | authn | B active-probe | M3 | `authn.rate-limit-missing` |
| 48 | werkzeug-debug-pin-derivation | recon | B active-probe | M3 | `recon.werkzeug-debug-pin-derivation` |
| 49 | oidc-email-claim-trust | authn | B active-probe | M3 | `authn.oidc-email-claim-trust` |
| 50 | user-enumeration | authn | B active-probe | M3 | `authn.user-enumeration` |
| 51 | password-reset-token-predictable | authn | B active-probe | M3 | `authn.password-reset-token-predictable` |
| + | exposed-git-directory | leak | A passive-pattern | M2 | `leak.exposed-git-directory` |
| + | web-cache-deception-poisoning | appsec | B active-probe | M3 | `appsec.web-cache-deception-poisoning` |
| + | open-cloud-storage-bucket | baas | D config+probe | M5 | `baas.open-cloud-storage-bucket` |
| + | http-request-smuggling | injection | B active-probe | M7 | `injection.http-request-smuggling` |
| + | insecure-deserialization | injection | B active-probe | M7 | `injection.insecure-deserialization` |
| + | account-takeover-chain | authn | B active-probe | M3 | `authn.account-takeover-chain` |
| + | websocket-auth-origin-bypass | appsec | B active-probe | M3 | `appsec.websocket-auth-origin-bypass` |

Milestone load (Top51+additions): {'M4': 5, 'M2': 13, 'M5': 4, 'M3': 24, 'M7': 12}