"use strict";

function parseHeaders(input) {
  // A pasted redirect chain may contain several response blocks.
  const blocks = input.split(/^\s*HTTP\/\d+(?:\.\d+)?[ \t]+\d{3}[^\r\n]*$/im);
  const headers = new Map();
  for (const line of blocks.at(-1).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const match = /^([!#$%&'*+.^_`|~\w-]+):[ \t]*(.*)$/.exec(line);
    if (!match) throw new Error("Paste raw response headers, one Name: value pair per line.");
    const [, name, value] = match;
    const key = name.toLowerCase();
    if (!headers.has(key)) headers.set(key, []);
    headers.get(key).push(value.trim());
  }
  if (!headers.size) throw new Error("Paste at least one response header to begin.");
  return headers;
}

function inspect(headers) {
  const observed = name => headers.get(name.toLowerCase()) ?? [];
  const values = name => observed(name).map(value => value.toLowerCase());
  const has = (name, value) => values(name).includes(value);
  const csp = values("Content-Security-Policy");
  const framing = csp.some(policy => /(?:^|[;,])\s*frame-ancestors\s+[^;,\s]/.test(policy));
  const checks = [
    ["Content-Security-Policy", csp.some(Boolean), "Limits where the browser can load resources from. Review the enforced directives for your application. A report-only policy does not enforce restrictions."],
    ["X-Frame-Options", has("X-Frame-Options", "deny") || has("X-Frame-Options", "sameorigin"), framing ? "An enforced CSP includes frame-ancestors. Review its allowed origins. X-Frame-Options is optional for browsers that enforce that directive." : "Prefer a CSP frame-ancestors directive. For legacy browser support, set X-Frame-Options: DENY if framing is unnecessary, or SAMEORIGIN if only same-origin framing is needed."],
    ["Strict-Transport-Security", values("Strict-Transport-Security").some(value => /(?:^|;)\s*max-age\s*=\s*0*[1-9][0-9]*\s*(?:;|$)/.test(value)), "Use a positive max-age on HTTPS responses. Enable includeSubDomains only when all subdomains are ready for HTTPS."],
    ["X-Content-Type-Options", has("X-Content-Type-Options", "nosniff"), "Set nosniff and serve resources with the correct Content-Type."],
    ["Referrer-Policy", /^(no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)$/.test(values("Referrer-Policy").join(",").split(",").at(-1).trim()), "Consider strict-origin-when-cross-origin or no-referrer, depending on how much referrer information the site needs to share."],
    ["Cross-Origin-Opener-Policy", has("Cross-Origin-Opener-Policy", "same-origin"), "Consider same-origin for strict opener isolation. Check compatibility with sign-in and payment popups."],
  ];
  const findings = checks.map(([name, detected, guidance]) => {
    const current = observed(name);
    const optional = name === "X-Frame-Options" && framing;
    const state = current.length
      ? (detected ? "Setting detected" : "Present · Review recommended")
      : (optional ? "Missing · CSP alternative present" : "");
    return { name, current, state, guidance, needsReview: !detected && !optional };
  });

  const deprecated = [
    ["X-XSS-Protection", "Remove this legacy browser filter header and use an enforced Content Security Policy."],
    ["Expect-CT", "Remove this header. Modern browsers enforce their own Certificate Transparency requirements."],
    ["Public-Key-Pins", "Remove HTTP public key pinning. Use standard TLS certificate validation and certificate monitoring."],
    ["Public-Key-Pins-Report-Only", "Remove this legacy pinning report header and use certificate monitoring."],
  ];
  for (const [name, guidance] of deprecated) {
    const current = observed(name);
    if (current.length) findings.push({ name, current, guidance, deprecated: true, needsReview: true });
  }
  return findings;
}

const form = document.querySelector("#inspector");
const input = document.querySelector("#headers");
const results = document.querySelector("#results");
const findings = document.querySelector("#findings");
const status = document.querySelector("#status");
const responseDetails = document.querySelector("#response-details");
const urlForm = document.querySelector("#url-inspector");
const urlStatus = document.querySelector("#url-status");
let pending;

function cancelUrlCheck() {
  pending?.abort();
  pending = undefined;
  urlStatus.textContent = "";
}

function resetResults() {
  responseDetails.hidden = true;
  responseDetails.textContent = "";
  findings.replaceChildren();
  results.hidden = true;
  status.textContent = "";
}

function renderChecks(checks, limited = false) {
  const groups = new Map();
  for (const check of checks) {
    const group = check.deprecated ? "Deprecated Security Headers"
      : check.current.length ? "Present Security Headers"
      : limited ? "Headers Unavailable to Browser"
      : "Missing Security Headers";
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(check);
  }
  for (const title of ["Missing Security Headers", "Deprecated Security Headers", "Present Security Headers", "Headers Unavailable to Browser"]) {
    const entries = groups.get(title) ?? [];
    if (!entries.length && title !== "Deprecated Security Headers") continue;
    const section = document.createElement("section");
    section.className = "finding-group";
    const heading = document.createElement("h3");
    heading.textContent = title;
    section.append(heading);
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.textContent = limited
        ? "No deprecated security headers found in the browser-visible response."
        : "No deprecated security headers found";
      section.append(empty);
    }
    for (const check of entries) section.append(renderFinding(check, limited));
    findings.append(section);
  }
  results.hidden = false;
}

function renderFinding({ name, current, state: findingState, guidance, needsReview }, limited) {
  const card = document.createElement("article");
  card.className = "finding";
  const heading = document.createElement("h4");
  heading.textContent = name;
  const state = document.createElement("p");
  state.className = "state";
  const unobservable = limited && !current.length;
  state.textContent = unobservable ? "" : findingState ?? "";
  const detail = document.createElement("p");
  detail.textContent = needsReview && !unobservable ? "Recommended: " + guidance : guidance;
  card.append(heading);
  if (state.textContent) card.append(state);
  if (current.length) {
    const label = document.createElement("p");
    label.textContent = current.length === 1 ? "Observed value" : "Observed values";
    card.append(label);
    for (const value of current) {
      const code = document.createElement("pre");
      code.className = "header-value";
      code.textContent = value || "(empty value)";
      card.append(code);
    }
  }
  card.append(detail);
  return card;
}

urlForm.addEventListener("submit", async event => {
  event.preventDefault();
  cancelUrlCheck();
  resetResults();
  const url = new URL(document.querySelector("#target-url").value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    urlStatus.textContent = "Enter an HTTP or HTTPS URL without embedded credentials.";
    return;
  }
  url.hash = "";
  const request = new AbortController();
  pending = request;
  const timer = setTimeout(() => request.abort(), 12000);
  urlStatus.textContent = "Checking URL…";
  try {
    const response = await fetch(url, {
      cache: "no-store", redirect: "follow", credentials: "omit", referrerPolicy: "no-referrer",
      signal: request.signal,
    });
    if (response.body) void response.body.cancel().catch(() => {});
    if (pending !== request) return;
    const headers = new Map(Array.from(response.headers, ([name, value]) => [name, [value]]));
    const limited = response.type === "cors";
    renderChecks(inspect(headers), limited);
    responseDetails.textContent = "Final URL: " + response.url + "\nHTTP status: " + response.status;
    responseDetails.hidden = false;
    urlStatus.textContent = limited
      ? "Review complete for browser-visible headers. Paste the full response headers to check any unavailable values."
      : "Review complete for the final response.";
  } catch {
    if (pending === request) {
      urlStatus.textContent = request.signal.aborted
        ? "The request timed out. Try again or use Paste headers."
        : "The browser could not read the response. Check the URL and connection, or use Paste headers if the site blocks cross-origin access.";
    }
  } finally {
    clearTimeout(timer);
    if (pending === request) pending = undefined;
  }
});

form.addEventListener("submit", event => {
  event.preventDefault();
  cancelUrlCheck();
  resetResults();
  try {
    const checks = inspect(parseHeaders(input.value));
    renderChecks(checks);
    status.textContent = "Header review complete. Findings apply to the pasted header block and do not establish whether a site is vulnerable.";
  } catch (error) {
    status.textContent = error.message;
  }
});

function clearPasteResults() {
  cancelUrlCheck();
  resetResults();
}

input.addEventListener("input", clearPasteResults);
form.addEventListener("reset", clearPasteResults);
document.querySelector("#example").addEventListener("click", () => {
  input.value = [
    "HTTP/2 200",
    "Content-Type: text/html; charset=utf-8",
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security: max-age=31536000",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
    "X-XSS-Protection: 1; mode=block",
  ].join("\n");
  form.requestSubmit();
});
