# Ranked runtime-vulnerability catalog (P3: scored, deduped, adversarially reviewed)

From 269 raw entries → 266 scored → 66 distinct clusters → **Top 51** + 6 adversarial-panel additions + 16 extended. Panel lenses: bug-bounty-realist, runtime-detectability, coverage-gaps. 0 removed.

## Top 51 (ranked)

| # | vuln | pack | sev | frameworks | why |
|---|------|------|-----|-----------|-----|
| 1 | **idor-bola** | access-control | 🔴 critical | agnostic,express,React,Django REST Framework | Highest-impact, highest-prevalence runtime class (22 members, comp=100, #1 OWASP API). All |
| 2 | **exposed-env-file** | leak | 🔴 critical | agnostic,Laravel,Django,Node.js/Express | Pure HTTP GET, zero-FP, live secrets. Promoted by both realist and runtime lenses. Note: / |
| 3 | **supabase-rls-open-table** | baas | 🔴 critical | Supabase,Firebase,PocketBase,Appwrite | The single confirmed-active validation engine KeyLeak actually has (baas_validator.py: ano |
| 4 | **env-secrets-in-js-bundle** | leak | 🔴 critical | React,Create React App,Vite,Next.js | comp=100 critical, KeyLeak core competency (regex/entropy mining over fetched bundles — re |
| 5 | **supabase-service-role-key-exposed** | leak | 🔴 critical | Supabase,Hasura | Leaked service_role/admin secret = full-DB compromise; detected directly in bundles/respon |
| 6 | **baas-config-exposed** | baas | 🔴 critical | React,Firebase,Supabase,Amplify | Canonical BaaS entry probe (comp=96) that pivots to RLS testing; trivially extracted from  |
| 7 | **unauthenticated-api-access** | access-control | 🔴 critical | Next.js,gin,echo,FastAPI | Missing-auth route, comp=100 critical, trivially confirmed by an unauthenticated GET (a pr |
| 8 | **exposed-source-maps** | leak | 🟠 high | agnostic,React,Vue,Angular | GET of sourceMappingURL leaks full source incl. secrets; real and implemented (browser_sca |
| 9 | **subdomain-takeover** | recon | 🟠 high | agnostic | Realist's strongest single correction: dramatically under-ranked at score 58. Dangling-CNA |
| 10 | **default-credentials** | authn | 🔴 critical | WordPress,Jenkins,Grafana,Adminer | Was not even in the prior Top 51. Promoted by both realist and coverage-gaps: critical-ATO |
| 11 | **token-in-webstorage** | client | 🟠 high | agnostic,React,Angular,Vue | Runtime lens promotes (genuinely implemented: passive localStorage/sessionStorage/IndexedD |
| 12 | **secret-in-dom** | leak | 🟠 high | agnostic,React,Redux,Zustand | Runtime lens promotes (real passive DOM/Redux/Vuex store mining, KeyLeak strength). Realis |
| 13 | **debug-endpoint-exposure** | recon | 🔴 critical | agnostic,express,Django,Flask | Broadest recon-grade HTTP-probe class (20 members, comp=95). Same trivial GET+marker shape |
| 14 | **spring-actuator-exposed** | recon | 🔴 critical | Spring Boot,Spring Actuator | Framework-bound, low-FP, reliably accepted (promoted by realist). /actuator/{env,heapdump, |
| 15 | **sqli** | injection | 🔴 critical | agnostic,Flask,PHP,Laravel | Highest-impact injection primitive and a class any appsec scanner must enumerate. BUT runt |
| 16 | **ssrf** | injection | 🔴 critical | agnostic,express,FastAPI,net/http | Highest single-class EV once landed (cloud-metadata -> IAM creds); realist even calls it u |
| 17 | **nosql-injection** | injection | 🔴 critical | express,mongoose,mongodb,Node.js | Highly prevalent in Node stacks, comp=96. Runtime lens demotes: no $ne/$gt mutation probe  |
| 18 | **jwt-flaw** | authn | 🔴 critical | agnostic,express,net/http,gin | Full-ATO impact, broad spread. Runtime lens demotes: scanner decodes JWTs but does NOT for |
| 19 | **cors-misconfig** | headers | 🟠 high | agnostic,express,FastAPI,React | 14 members, ubiquitous. Runtime lens demotes: only the BaaS CORS=='*' check is active; the |
| 20 | **mass-assignment** | injection | 🔴 critical | agnostic,express,Ruby on Rails,Laravel | OWASP API6, 12 members across all ORMs. Runtime lens demotes: no privileged-field write-pr |
| 21 | **bfla** | access-control | 🔴 critical | agnostic,Spring,Next.js,ASP.NET | OWASP API5, high impact. Partially confirmable via the same 2-user replay machinery as IDO |
| 22 | **nextjs-middleware-authz-bypass** | access-control | 🔴 critical | Next.js | CVE-class x-middleware-subrequest bypass; framework-bound, high prevalence given Next.js d |
| 23 | **path-traversal** | injection | 🔴 critical | agnostic,express,Flask,Ruby on Rails | High-impact file-read primitive, 8 frameworks, clean oracle (read /etc/passwd). Runtime le |
| 24 | **ssti** | injection | 🔴 critical | Flask,Jinja2,Twig,FreeMarker | Escalates to RCE; clean {{7*7}} oracle. Runtime lens demotes: no arithmetic-payload reflec |
| 25 | **open-redirect** | injection | 🟠 high | agnostic,express,Flask,Ruby on Rails | Realist promotes (OAuth-code/token-leak variant is ATO-grade, not the informational redire |
| 26 | **h2-console-exposed** | recon | 🔴 critical | Spring Boot | Framework-bound single-path /h2-console probe -> DB RCE, near-zero FP. Runtime lens flags  |
| 27 | **otp-in-response** | authn | 🔴 critical | agnostic | Full MFA defeat; detected by response-body regex which the scanner genuinely does (runtime |
| 28 | **secret-in-response-body** | leak | 🔴 critical | Django,Laravel | SECRET_KEY/Sanctum token echoed in body = direct leakage caught by body scanning (runtime  |
| 29 | **spring-data-rest-exposure** | recon | 🔴 critical | Spring Boot,Spring Data REST | Auto-exposed repositories enable CRUD enumeration; distinct path-signature detection (sing |
| 30 | **directory-listing** | recon | 🟡 medium | express,serve-static,Apache,Nginx | Runtime lens promotes (genuinely implemented marker-based HTTP detection, low-FP, high pre |
| 31 | **xss-reflected-stored-dom** | appsec | 🟠 high | agnostic,Ruby on Rails,Flask,React | Most prevalent client-side bug. Reflected variant is lead-only (no active reflection probe |
| 32 | **excessive-data-exposure** | api | 🟠 high | agnostic | OWASP API3; detected by inspecting response bodies for over-broad objects — a natural resp |
| 33 | **weak-session-secret** | authn | 🔴 critical | Flask,Ruby on Rails | Forgeable Flask/Rails signed session = full forgery. Runtime lens demotes (minting a valid |
| 34 | **open-cloud-storage-bucket** | baas | 🟠 high | Supabase,Firebase,AWS S3,GCS | Net-new from runtime lens (open-cloud-storage-bucket) folded in here as an extension of th |
| 35 | **client-side-only-authz** | access-control | 🟠 high | React,React Router,Next.js,LaunchDarkly | UI-only/feature-flag authz bypassed by direct API call; KeyLeak's JS endpoint-mining feeds |
| 36 | **graphql-introspection-exposed** | api | 🟡 medium | GraphQL,Hasura,Apollo,React | Realist promotes (reliably accepted, low-FP, clean __schema oracle). Runtime lens caveat:  |
| 37 | **insecure-cookie-flags** | headers | 🟠 high | agnostic,express,Flask,ASP.NET | Both realist and runtime lenses flag this: realist demotes payout (informational unless ch |
| 38 | **laravel-debugbar-telescope-exposed** | recon | 🟠 high | Laravel | Framework-bound, exposes queries/env/request data via specific path+marker. Same trivial G |
| 39 | **go-pprof-debug-exposed** | recon | 🟠 high | net/http | /debug/pprof on default mux leaks memory/goroutine data + DoS. Specific-path probe, common |
| 40 | **host-header-injection** | appsec | 🟠 high | agnostic,Django,go | Realist promotes (password-reset-poisoning variant is straight ATO). Runtime lens demotes  |
| 41 | **cmd-injection** | injection | 🔴 critical | agnostic | Coverage-gaps promotes: critical-RCE with a clean time-blind/OOB oracle, ranked far below  |
| 42 | **resource-id-enumeration** | api | 🟠 high | agnostic | OWASP API9; sequential/guessable IDs + legacy API versions enumerable via ID fuzzing and v |
| 43 | **xxe-injection** | injection | 🔴 critical | Java,PHP,.NET,Python (lxml) | Coverage-gaps promotes: critical impact, clean OOB oracle, under-ranked at 73 and not in p |
| 44 | **token-in-query-string** | leak | 🟡 medium | FastAPI,React,agnostic | Tokens/PII in URL/query leak via logs/referrers; detected directly in request URLs/links — |
| 45 | **prototype-pollution** | injection | 🔴 critical | agnostic,express,body-parser,Next.js | Can escalate to RCE/authz bypass in Node. Runtime lens demotes (no __proto__ payload engin |
| 46 | **django-admin-exposed** | recon | 🟠 high | Django,Django REST Framework | Specific-path /admin + DRF browsable API probe, very common in Django. Same GET+marker sha |
| 47 | **rate-limit-missing** | authn | 🟠 high | agnostic,FastAPI,go,express | OWASP API4; brute-force/credential-stuffing on auth/OTP. Runtime lens demotes (no burst-ti |
| 48 | **werkzeug-debug-pin-derivation** | recon | 🔴 critical | Flask,Werkzeug | Interactive debugger console = RCE; distinct high-impact Flask finding via specific endpoi |
| 49 | **oidc-email-claim-trust** | authn | 🔴 critical | agnostic | Trusting unverified OIDC email claim -> ATO via attacker IdP. Runtime lens demotes (auth-f |
| 50 | **user-enumeration** | authn | 🟡 medium | agnostic,ASP.NET,Ruby on Rails,Django | Both realist and runtime lenses demote (heavily duplicated, routinely informational, no re |
| 51 | **password-reset-token-predictable** | authn | 🟠 high | agnostic | Coverage-gaps promotes; sits at the economic center of the bounty ATO-chain. The password- |

## Adversarial-panel additions (gaps the Top 51 missed)

| vuln | pack | sev | why |
|------|------|-----|-----|
| **exposed-git-directory** | leak | 🔴 critical | Realist add + coverage-gaps confirm the gap is real (verified: no .git/config, backup, or .DS_Store probe exis |
| **web-cache-deception-poisoning** | appsec | 🟠 high | Named independently by all three lenses (realist 'cache-deception-poisoning', coverage-gaps 'web-cache-decepti |
| **http-request-smuggling** | injection | 🔴 critical | Coverage-gaps: top-tier class with ZERO cluster representation. Genuine high-impact gap, black-box detectable  |
| **insecure-deserialization** | injection | 🔴 critical | Coverage-gaps: generic insecure deserialization has no cluster (aspnet-viewstate is the only narrow representa |
| **account-takeover-chain** | authn | 🔴 critical | Realist add: explicit ATO-chain class fusing reset-token + response-leaked-OTP + identity-claim confusion (the |
| **websocket-auth-origin-bypass** | appsec | 🟠 high | Coverage-gaps: WebSocket auth / cross-site WebSocket hijacking (CSWSH) has zero cluster representation. Black- |

## Extended (ranked after Top 51)

- 🟡 **OpenAPI / Swagger Docs Exposed (FastAPI /docs)** (debug-endpoint-exposure)
- 🟠 **GraphQL Query Batching / Aliasing DoS Amplification** (graphql-batching-amplification)
- 🔴 **ASP.NET ViewState MAC Disabled (deserialization integrity bypass)** (deserialization-integrity-bypass)
- 🟡 **phpinfo() Page Exposed** (debug-endpoint-exposure)
- 🟠 **Auth Token Logged to Telemetry / Console (Angular interceptor leakage)** (secrets-exposure)
- 🟠 **Session Fixation (no session ID rotation on login)** (session-fixation)
- 🟠 **Missing/Disabled CSRF Protection (incl. OAuth state)** (csrf)
- 🟡 **Missing Security Headers / CSP (HSTS, X-Frame, CSP)** (security-headers)
- 🟡 **Missing Subresource Integrity on Third-Party Scripts** (missing-sri)
- ⚪ **Server / Tech / Version Disclosure (Server, X-Powered-By headers)** (version-disclosure)
- ⚪ **robots.txt / sitemap Path Disclosure** (information-disclosure)
- 🟡 **Clickjacking (missing X-Frame-Options / frame-ancestors)** (clickjacking)
- 🟠 **Rails Default Catch-All Route / Action Exposure** (debug-endpoint-exposure)
- 🟡 **Pydantic Type-Coercion Input-Validation Bypass** (input-validation-bypass)
- ⚪ **Excessive / Unrestricted HTTP Methods (TRACE, PUT, DELETE)** (http-method-unrestricted)
- 🟠 **postMessage Origin Wildcard / Missing Origin Check** (postmessage-origin-bypass)
