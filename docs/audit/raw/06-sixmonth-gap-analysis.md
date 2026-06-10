# Six-Month Trending Exploit-Class Gap Analysis (Dec 2025 – Jun 2026)

**Purpose:** Identify the vulnerability/exploit *classes* most prominent in the last ~6 months, map which ones KeyLeak Detector can help developers "test for before they ship," and find the **gaps** where KeyLeak currently does nothing.

**Method:** WebSearch/WebFetch over Dec 2025–Jun 2026 incidents, CVEs, and advisories. Coverage baseline read from `keyleak/detectors.py` (72 string detectors), `keyleak/baas_validator.py` (active Supabase RLS probing), `keyleak/js_library_cves.py` (retire.js-style), `keyleak/browser_scanner.py`, `keyleak/site_scanner.py`, `keyleak/local_scanner.py`, and `docs/vuln-research/catalog/RANKED.md`.

**Scope rule:** Prioritized **runtime-detectable / pre-ship-checkable** classes (findable by scanning a running app, a repo, a built bundle, or config). Memory-corruption CVEs (e.g. Ollama `CVE-2026-7482` GGUF OOB) are noted only where the *exposure* (unauthenticated endpoint on the internet) is the checkable part.

---

## What KeyLeak covers today (baseline)

- **72 string/secret detectors** (`detectors.py`): AI provider keys (OpenAI/Anthropic/OpenRouter/Gemini/HF/Groq/Perplexity/Anyscale/Replicate), cloud keys (AWS/GCP SA/Firebase), Stripe, Slack, GitHub PAT, GitLab, npm token, SendGrid, PyPI, DB URLs, private keys, JWT/bearer, `mcp_config_secret`, `hidden_prompt_injection`, `graphql_introspection_hint`, `source_map_reference`.
- **Shai-Hulud IOC pack (leak):** `npm_optional_dep_git_ref`, `gh_actions_pull_request_target`, `gh_actions_secrets_tojson`, `shai_hulud_c2_domain`, `npm_prepare_bun_payload`.
- **BaaS validator (ACTIVE probing, `baas_validator.py`):** Supabase anon-key reachability, RLS open-table read, `baas_cors_wildcard`, PostgREST `/rest/v1/` OpenAPI table enumeration, read/write probes. Plus static config detectors for Firebase/Appwrite/PocketBase.
- **Browser/bundle scanner:** env-in-bundle, source maps, token-in-webstorage, secret-in-DOM, `vulnerable_js_library` (retire.js-style, **only jQuery + Bootstrap** in `VULN_TABLE`).
- **Site scanner:** subdomain enumeration + `subdomain_takeover.py`, limited admin/graphql path probing.
- **Local scanner:** `.git`, `.env`, `.github/workflows` / `.gitlab-ci.yml` scanning; lead-only detectors for IDOR/SQLi/XSS/auth-bypass (signal, not confirmation).

---

## 1. Top ~20 trending exploit classes (Dec 2025 – Jun 2026)

| # | Class | Window source (URL) | Detectable pre-ship? | KeyLeak status | Detector id / note |
|---|-------|---------------------|----------------------|----------------|--------------------|
| 1 | **npm self-propagating worm / Shai-Hulud lineage** (Sha1-Hulud 2.0, "Miasma", Mini Shai-Hulud, "Third Coming") | [Wiz Sha1-Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack); [Hacker News modified strain Dec 2025](https://thehackernews.com/2025/12/researchers-spot-modified-shai-hulud.html); [StepSecurity Mini Shai-Hulud May 2026](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) | Yes (repo/lockfile/IOC scan) | **Partial** | `npm_optional_dep_git_ref`, `shai_hulud_c2_domain`, `npm_prepare_bun_payload` cover the *original* IOC shape; new C2 hosts + `environment_source.js`/`bun_installer.js` filenames + new descriptions are NOT in the IOC set |
| 2 | **Malicious npm lifecycle scripts (preinstall/postinstall Bun-staged credential stealer)** — Bitwarden CLI, node-ipc, Red Hat `@redhat-cloud-services` (Miasma), 33-pkg dependency-confusion | [Microsoft: Red Hat Miasma preinstall→persistence](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/); [StepSecurity Bitwarden CLI hijack](https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools) | Yes (manifest scan of installed deps) | **GAP** (partial) | `npm_prepare_bun_payload` matches one payload shape in source files; there is **no scan of `node_modules/*/package.json` for any preinstall/postinstall/prepare lifecycle hook** added by deps |
| 3 | **Leaked AI-provider API keys (OpenAI/Anthropic/Gemini) in repos, bundles, client JS** — leaks grew 81% YoY; discovery→abuse collapsed to minutes | [GitGuardian via SecureStartKit](https://securestartkit.com/blog/exposed-api-keys-how-ai-tools-leak-your-secrets-and-how-to-lock-them-down); [Cyble: 5k repos + 3k live sites leaking ChatGPT keys](https://safeguard.sh/resources/blog/openai-api-key-leakage-on-github-at-scale) | Yes (repo + bundle + live-site scan) | **Covered** | `openai_api_key`, `anthropic_api_key`, `gemini_api_key`, +6 more provider detectors |
| 4 | **Supabase RLS misconfig / disabled RLS** — Moltbook (1.5M API keys, Jan–Feb 2026); 83% of Supabase incidents are RLS; CVE-2025-48757 (170+ Lovable apps) | [Moltbook hack writeup](https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding); [VibeAppScanner: RLS trap & CVE-2025-48757](https://vibeappscanner.com/is-supabase-safe) | Yes (active anon-key probe) | **Covered** | `baas_validator.py` `supabase-rls-open-table` — KeyLeak's single confirmed-active validation engine |
| 5 | **Exposed `service_role` / admin BaaS keys in client code** | [VibeAppScanner anon vs service_role](https://vibeappscanner.com/is-supabase-safe); [byteiota 170+ apps](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/) | Yes (bundle/response scan) | **Covered** | `supabase-service-role-key-exposed` (leak pack); but verify a dedicated `service_role` JWT-role detector exists vs anon |
| 6 | **GitHub Actions `pull_request_target` "Pwn Request" → secret exfil** — prt-scan (500+ PRs, Mar–Apr 2026), Megalodon (5,500+ repos, May 2026), hackerbot-claw (Feb 2026) | [StepSecurity Megalodon](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories); [Orca pull_request_nightmare](https://orca.security/resources/blog/pull-request-nightmare-part-2-exploits/) | Yes (workflow YAML scan) | **Covered** | `gh_actions_pull_request_target`, `gh_actions_secrets_tojson` |
| 7 | **CI/CD OIDC-token / GITHUB_TOKEN exfiltration via injected workflow** (Megalodon backdoored CI files; Red Hat OIDC publish abuse) | [Microsoft Miasma OIDC publish](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/) | Partial (workflow scan for over-broad `permissions:`, unpinned `uses:`) | **GAP** | No detector for unpinned `uses: org/action@tag`, over-broad `permissions: write-all`, or workflow secret-in-`run`-echo |
| 8 | **MCP tool poisoning / unauthenticated MCP server / hardcoded creds in MCP config** — multiple CVSS 9.0+ in H1 2026; `~/.claude.json` + MCP configs explicitly targeted | [ITECS MCP tool poisoning 2026](https://itecsonline.com/post/mcp-tool-poisoning-enterprise-ai-agent-security-2026); [Equixly offensive MCP](https://equixly.com/blog/2026/02/26/offensive-security-for-mcp-servers/); [StepSecurity Bitwarden (targets MCP configs)](https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools) | Yes (config-file scan) | **Partial** | `mcp_config_secret` finds secrets *in* MCP config; no check for **MCP server with no auth**, tool-description poisoning markers, or risky tool grants |
| 9 | **Indirect prompt injection → data exfiltration (RAG / agent / email)** — EchoLeak-class zero-click (CVE-2025-32711 lineage), poisoned-email→SSH-key exfil (~80% success) | [arXiv EchoLeak](https://arxiv.org/pdf/2509.10540); [arXiv indirect PI in the wild Jan 2026](https://arxiv.org/pdf/2601.07072); [Microsoft: indirect injection in MCP](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp) | Partial (static hidden-instruction scan only) | **Partial** | `hidden_prompt_injection` detects hidden instructions in *files*; no scan of retrieved/served content, no runtime exfil-channel (markdown image/URL beacon) detection |
| 10 | **Exposed unauthenticated LLM inference endpoints (Ollama et al.)** — ~12k–300k internet-exposed Ollama servers; default no-auth API leaks keys/prompts/creds | [LeakIX 12k Ollama exposed Feb 2026](https://blog.leakix.net/2026/02/ollama-exposed/); [Security Boulevard Mar 2026](https://securityboulevard.com/2026/03/exposed-ollama-servers-security-risks-of-publicly-accessible-llm-infrastructure/) | Yes (active HTTP probe `/api/tags`) | **GAP** | No probe for `/api/tags`, `/v1/models`, or other unauth model-server fingerprints |
| 11 | **Spring Boot Actuator authorization bypass / exposed actuator** — CVE-2026-40976 (CVSS 9.1, Apr 2026), CVE-2026-22731/22733 | [HeroDevs CVE-2026-40976](https://www.herodevs.com/blog-posts/cve-2026-40976-spring-boot-4-0-actuator-authorization-bypass); [securityonline 2 high-sev flaws](https://securityonline.info/spring-boot-authentication-bypass-actuator-flaws-cve-2026-22731/) | Yes (active probe `/actuator/env`,`/heapdump`) | **GAP** | RANKED.md ranks `spring-actuator-exposed` #14 but no active `/actuator/*` probe is implemented; only path-mention leads |
| 12 | **Next.js middleware authorization bypass** — CVE-2026-44575 (.rsc/segment-prefetch variant, May 2026); successor to CVE-2025-29927 | [Security Boulevard CVE-2026-44575](https://securityboulevard.com/2026/05/cve-2026-44575-middleware-authorization-bypass-in-next-js-app-router/); [Vercel GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw) | Yes (active probe: send `.rsc` / `x-middleware-subrequest`) | **GAP** | RANKED.md #22 lists `nextjs-middleware-authz-bypass` but no active 2-request bypass probe |
| 13 | **Exposed `.env` files on live hosts** — 28.65M new hardcoded secrets on GitHub in 2025 (+34%); .env mishandled by coding agents | [Snyk State of Secrets 2025/26](https://snyk.io/articles/state-of-secrets/); [Knostic .env coding-agent leakage](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage) | Yes (active GET `/.env`) | **Partial** | Local `.env` file scan exists; **live `GET /.env` probe** on a deployed URL is the RANKED #2 class but appears absent from the active scanner |
| 14 | **Exposed `.git` directory on live hosts** | [Medium GitHub Dorking 2026 guide](https://medium.com/@thenewdate24/github-dorking-the-complete-2026-hunters-guide-to-finding-exposed-secrets-9a72331ed5bb) | Yes (active GET `/.git/config`) | **GAP** | RANKED.md adversarial add `exposed-git-directory` confirms no live `.git/config`/backup probe exists |
| 15 | **Source-map secret leakage on live bundles** — `.map` files reconstruct source incl. hardcoded Stripe secret keys → unauthorized payments | [Sentry: Abusing Exposed Sourcemaps](https://blog.sentry.security/abusing-exposed-sourcemaps/) | Yes (fetch `sourceMappingURL`, scan content) | **Covered** | `exposed-source-maps` (`browser_scanner.py` + `source_map_reference` detector + `sourcemaps.py`) |
| 16 | **Env secrets baked into client JS bundle (NEXT_PUBLIC_ etc.)** | [DEV: Next.js env vars NEXT_PUBLIC](https://dev.to/whoffagents/nextjs-environment-variables-nextpublic-server-only-secrets-and-startup-validation-5f1d) | Yes (bundle scan) | **Covered** | `env-secrets-in-js-bundle` (RANKED #4) |
| 17 | **Typosquat / dependency-confusion packages stealing cloud+CI/CD secrets** | [Microsoft typosquat cloud/CI secrets May 2026](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/); [Microsoft 33-pkg dependency confusion](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/) | Partial (manifest heuristics) | **GAP** | No detector for internal-scope packages resolving to public registry, or known-bad package-name list |
| 18 | **CORS wildcard / overly permissive CORS on APIs** | [AuditYourApp Supabase/Firebase API best practices 2026](https://www.audityour.app/blog/api-security-best-practices) | Yes (active OPTIONS/Origin reflection probe) | **Partial** | Only `baas_cors_wildcard` (BaaS-specific `access-control-allow-origin: *`); no generic CORS Origin-reflection probe on arbitrary API hosts |
| 19 | **IDOR / BOLA (OWASP API #1)** — still highest-prevalence runtime API class | RANKED.md #1; general 2026 API-security guidance | Partial (needs 2-user replay) | **Partial** | `idor_direct_object_lead` is signal-only; the 2-user replay confirmation machinery is the high-value missing active check |
| 20 | **Vulnerable client-side JS libraries (beyond jQuery/Bootstrap)** | [Sentry sourcemaps + general retire.js usage](https://blog.sentry.security/abusing-exposed-sourcemaps/) | Yes (version → CVE map) | **Partial** | `vulnerable_js_library` exists but `VULN_TABLE` only has jQuery + Bootstrap; React/Angular/Vue/Next/lodash/axios CVEs absent |

Honorable mentions in the window (lower pre-ship leverage, noted for completeness):
- **OAuth/JWT misconfig & OIDC email-claim trust** — RANKED #18/#49; partial (JWT decode only, no `alg:none`/weak-secret forge probe). [UNVERIFIED single dominant window incident — trend is steady, not a named spike.]
- **Malicious marketplace "skills" (ClawHub) / agent supply chain** — emerging; see [cyberdesserts AI agent risks](https://blog.cyberdesserts.com/ai-agent-security-risks/). Pre-ship checkability low for now.

---

## 2. The GAP list — ranked by (prevalence × impact × cheap-to-add)

Rank weights: how common in-window × blast radius × how little code KeyLeak needs. Effort: **S** = a detector/regex or one HTTP probe; **M** = a small new scanner module or multi-request probe; **L** = new subsystem.

| Rank | Gap class | Check shape | What it would look like | Effort |
|------|-----------|-------------|--------------------------|--------|
| 1 | **Live `GET /.env` + `/.git/config` probe** (RANKED #2 + adversarial add) | Active probe | On a deployed URL, `GET /.env`, `/.git/config`, `/.git/HEAD`, common backups (`.env.bak`, `config.php~`, `.DS_Store`). Zero-FP marker match (`APP_KEY=`, `[core]`). | **S** |
| 2 | **Dependency lifecycle-hook scanner** (Bitwarden/node-ipc/Miasma class) | Repo/manifest scan | Walk `node_modules/*/package.json` (or lockfile + on-disk) flagging any `preinstall`/`install`/`postinstall`/`prepare` script in a *dependency*; surface ones spawning `bun`, `curl`, `node -e`, base64. | **M** |
| 3 | **Spring Actuator + framework debug-endpoint active probe** (CVE-2026-40976 class) | Active probe | `GET /actuator/env`,`/actuator/heapdump`,`/actuator/configprops`; Flask `/console`, Django `/admin`, `/debug`, FastAPI `/docs`, Laravel `/_debugbar`, Go `/debug/pprof`, `/h2-console`. Marker-confirmed. | **M** |
| 4 | **Unauthenticated LLM/inference endpoint probe** (Ollama 12k–300k exposed) | Active probe | `GET /api/tags`, `/api/version` (Ollama), `/v1/models` (OpenAI-compatible servers), vLLM/LM Studio fingerprints; flag when reachable without auth. | **S** |
| 5 | **Next.js middleware authz-bypass active probe** (CVE-2026-44575 / -29927) | Active probe (2-req) | Fetch a protected route normally (expect 401/redirect), then with `.rsc` suffix / `x-middleware-subrequest` header; if the second returns 200 + protected content → confirmed. | **M** |
| 6 | **Refreshed Shai-Hulud/Miasma IOC set** | Repo scan | Add new C2 hosts, `environment_source.js` / `bun_installer.js` filenames, repo descriptions ("Second/Third Coming", "Goldox-T3chs"), and OIDC-publish-abuse markers to the IOC detectors. | **S** |
| 7 | **GitHub Actions hardening detectors** (Megalodon/prt-scan tail) | Workflow YAML scan | Flag unpinned `uses: org/action@<tag>` (not full SHA), `permissions: write-all`, secret echoed in `run:`, `actions/cache` in a `pull_request_target` job. | **S** |
| 8 | **MCP server posture check** (tool poisoning / no-auth) | Config + active | Parse MCP config for servers exposed without auth, over-broad tool grants, and tool descriptions containing imperative-injection markers ("ignore previous", "exfiltrate"). | **M** |
| 9 | **Generic CORS Origin-reflection probe** | Active probe | Send `Origin: https://evil.example`; if response reflects it in `access-control-allow-origin` *with* `allow-credentials: true` → critical. Generalizes the BaaS-only check. | **S** |
| 10 | **Expanded vulnerable-JS-library table** | Bundle/version scan | Extend `VULN_TABLE` beyond jQuery/Bootstrap: lodash, axios, Next.js (incl. CVE-2026-44575/-29927), Angular, Vue, moment, dompurify. | **S** |
| 11 | **Dependency-confusion / typosquat heuristic** | Manifest scan | Flag internal-scope deps resolvable from public registry; compare against a small known-bad/typo list. | **M** |
| 12 | **Prompt-injection exfil-channel scan** (EchoLeak class) | Bundle/template scan | Flag agent/RAG code that renders untrusted content into markdown images / auto-fetched URLs (the EchoLeak exfil primitive) and missing output-URL allowlists. | **L** |
| 13 | **2-user IDOR/BOLA replay** (RANKED #1) | Active multi-session | Replay an authenticated request with a second user's session; compare bodies for cross-tenant object access. | **L** |

---

## 3. The "protect yourself" angle — run-this-before-you-ship

For the top gaps, the concrete preventative a developer would run KeyLeak to verify:

1. **Before you deploy a web app:** `keyleak scan https://your-preview-url --probe exposed-files` → confirms `/.env`, `/.git/config`, and backup files are **not** publicly served. (Gap #1; today KeyLeak only checks these on the local repo, not the deployed surface.)
2. **Before you `npm install` / merge a dep bump:** `keyleak deps --lifecycle-hooks` → lists every dependency that ships a preinstall/postinstall/prepare hook and flags Bun-staging / curl-piping payloads. Pair with the existing CLAUDE.md rule `keyleak local . --launch-profile launch-gate --fail-on high`. (Gap #2.)
3. **Before you ship a Spring/Flask/Django/Next backend:** `keyleak scan https://your-url --probe debug-endpoints` → actively confirms `/actuator/env`, `/console`, `/debug/pprof`, etc. are not reachable (CVE-2026-40976 class). (Gap #3.)
4. **Before you expose an AI service:** `keyleak scan https://your-host --probe llm-endpoints` → confirms no unauthenticated Ollama `/api/tags` or `/v1/models` surface (12k–300k servers got this wrong in-window). (Gap #4.)
5. **Before you ship a Next.js App Router app:** `keyleak scan https://your-url --probe nextjs-authz` → sends the `.rsc`/`x-middleware-subrequest` variant against a protected route to confirm middleware authz holds (CVE-2026-44575). (Gap #5.)
6. **Before you merge a workflow change:** `keyleak local . --launch-profile launch-gate` already catches `pull_request_target` + `toJSON(secrets)`; extend with unpinned-`uses:` and `permissions: write-all` (Gap #7) so the same gate blocks the Megalodon pattern.

---

## Key cross-cutting finding

KeyLeak's **static secret detection is strong and current** (AI-provider keys, BaaS keys, Shai-Hulud original IOCs) and its **one confirmed-active engine — Supabase RLS probing — sits exactly on the single most-reported breach class of the window (Moltbook, CVE-2025-48757)**. The gaps cluster in two places:

- **Active deployed-surface probing** that RANKED.md already prioritizes but the code doesn't yet implement: live `/.env` + `/.git`, actuator/debug endpoints, unauthenticated LLM endpoints, Next.js middleware bypass, generic CORS. These are cheap (S/M) and map directly to named Dec 2025–Jun 2026 CVEs/campaigns.
- **Dependency/CI supply-chain depth beyond the original Shai-Hulud signature:** generic lifecycle-hook scanning, refreshed IOCs, and Actions hardening — the single most active attack *family* of the window (Sha1-Hulud 2.0, Miasma, Bitwarden CLI, node-ipc, Megalodon, prt-scan).

---

## Sources

- [Wiz: Sha1-Hulud 2.0 ongoing supply chain attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [The Hacker News: modified Shai-Hulud testing payload (Dec 2025)](https://thehackernews.com/2025/12/researchers-spot-modified-shai-hulud.html)
- [StepSecurity: Mini Shai-Hulud is back (May 2026)](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [Unit 42: monitoring npm supply chain attacks (updated Jun 2 2026)](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- [The Register: Shai-Hulud copycat worm (May 18 2026)](https://www.theregister.com/cyber-crime/2026/05/18/shai-hulud-copycat-hits-another-npm-package/5242180)
- [Microsoft: Red Hat npm Miasma preinstall→persistence (Jun 2 2026)](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
- [Mend: Miasma Red Hat Cloud Services packages](https://www.mend.io/blog/redhat-cloud-services-packages-drop-multi-cloud-credential-stealer/)
- [StepSecurity: Bitwarden CLI hijacked on npm](https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools)
- [Microsoft: typosquatted npm packages steal cloud/CI secrets (May 28 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/)
- [Microsoft: 33 malicious npm packages dependency confusion (May 29 2026)](https://www.microsoft.com/en-us/security/blog/2026/05/29/33-malicious-npm-packages-abuse-dependency-confusion-profile-developer-environments/)
- [Snyk: malicious node-ipc versions](https://snyk.io/blog/malicious-node-ipc-versions-published-npm/)
- [Safeguard/Cyble: OpenAI API key leakage at scale](https://safeguard.sh/resources/blog/openai-api-key-leakage-on-github-at-scale)
- [SecureStartKit: exposed API keys / AI tools leak secrets (Mar 2026)](https://securestartkit.com/blog/exposed-api-keys-how-ai-tools-leak-your-secrets-and-how-to-lock-them-down)
- [Snyk: State of Secrets — 28M leaked on GitHub in 2025](https://snyk.io/articles/state-of-secrets/)
- [Knostic: .env secret leakage by coding agents](https://www.knostic.ai/blog/claude-cursor-env-file-secret-leakage)
- [Blog OGOU: Moltbook hack — vibe coding leaks 1.5M API keys](https://blog.ogwilliam.com/post/moltbook-hack-supabase-vibe-coding)
- [VibeAppScanner: is Supabase safe — RLS trap & CVE-2025-48757](https://vibeappscanner.com/is-supabase-safe)
- [byteiota: Supabase flaw — 170+ apps exposed by missing RLS](https://byteiota.com/supabase-security-flaw-170-apps-exposed-by-missing-rls/)
- [DeepStrike: hacking thousands of misconfigured Supabase instances](https://deepstrike.io/blog/hacking-thousands-of-misconfigured-supabase-instances-at-scale)
- [StepSecurity: Megalodon — 5,500+ repos secret exfiltration (May 2026)](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories)
- [Orca: pull_request_nightmare part 2](https://orca.security/resources/blog/pull-request-nightmare-part-2-exploits/)
- [Cryptika: new GitHub Actions attack chain — fake CI updates (prt-scan)](https://www.cryptika.com/new-github-actions-attack-chain-uses-fake-ci-updates-to-exfiltrate-secrets-and-tokens/)
- [ITECS: MCP tool poisoning enterprise AI agent security 2026](https://itecsonline.com/post/mcp-tool-poisoning-enterprise-ai-agent-security-2026)
- [Equixly: offensive security for MCP servers (Feb 2026)](https://equixly.com/blog/2026/02/26/offensive-security-for-mcp-servers/)
- [Invariant Labs: MCP tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [arXiv: EchoLeak zero-click prompt injection](https://arxiv.org/pdf/2509.10540)
- [arXiv: indirect prompt injection in the wild (Jan 2026)](https://arxiv.org/pdf/2601.07072)
- [Microsoft Dev: protecting against indirect injection in MCP](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- [LeakIX: 12,000 Ollama instances exposed (Feb 2026)](https://blog.leakix.net/2026/02/ollama-exposed/)
- [Security Boulevard: exposed Ollama servers (Mar 2026)](https://securityboulevard.com/2026/03/exposed-ollama-servers-security-risks-of-publicly-accessible-llm-infrastructure/)
- [Indusface: CVE-2026-7482 Bleeding Llama](https://www.indusface.com/blog/cve-2026-7482-bleeding-llama-vulnerability/)
- [HeroDevs: CVE-2026-40976 Spring Boot Actuator authz bypass](https://www.herodevs.com/blog-posts/cve-2026-40976-spring-boot-4-0-actuator-authorization-bypass)
- [securityonline: Spring Boot actuator flaws CVE-2026-22731/22733](https://securityonline.info/spring-boot-authentication-bypass-actuator-flaws-cve-2026-22731/)
- [Security Boulevard: CVE-2026-44575 Next.js middleware authz bypass](https://securityboulevard.com/2026/05/cve-2026-44575-middleware-authorization-bypass-in-next-js-app-router/)
- [Vercel advisory GHSA-f82v-jwr5-mffw (Next.js middleware)](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Sentry: Abusing Exposed Sourcemaps](https://blog.sentry.security/abusing-exposed-sourcemaps/)
- [Medium: GitHub Dorking 2026 hunter's guide](https://medium.com/@thenewdate24/github-dorking-the-complete-2026-hunters-guide-to-finding-exposed-secrets-9a72331ed5bb)
- [AuditYourApp: API security best practices Supabase/Firebase 2026](https://www.audityour.app/blog/api-security-best-practices)
- [cyberdesserts: AI agent security risks 2026 (ClawHub/OpenClaw)](https://blog.cyberdesserts.com/ai-agent-security-risks/)
