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
  return checks.map(([name, detected, guidance]) => {
    const current = observed(name);
    const optional = name === "X-Frame-Options" && framing;
    const state = current.length
      ? (detected ? "Setting detected" : "Present · Review recommended")
      : (optional ? "Missing · CSP alternative present" : "Missing · Review recommended");
    return { name, current, state, guidance, needsReview: !detected && !optional };
  });
}

const form = document.querySelector("#inspector");
const input = document.querySelector("#headers");
const results = document.querySelector("#results");
const findings = document.querySelector("#findings");
const status = document.querySelector("#status");

function resetResults() {
  findings.replaceChildren();
  results.hidden = true;
  status.textContent = "";
}

form.addEventListener("submit", event => {
  event.preventDefault();
  resetResults();
  try {
    const checks = inspect(parseHeaders(input.value));
    for (const { name, current, state: findingState, guidance, needsReview } of checks) {
      const card = document.createElement("article");
      card.className = "finding";
      const heading = document.createElement("h3");
      heading.textContent = name;
      const state = document.createElement("p");
      state.className = "state";
      state.textContent = findingState;
      const detail = document.createElement("p");
      detail.textContent = needsReview ? "Recommended: " + guidance : guidance;
      card.append(heading, state);
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
      findings.append(card);
    }
    results.hidden = false;
    status.textContent = "Six checks complete. Findings apply to the pasted header block and do not establish whether a site is vulnerable.";
  } catch (error) {
    status.textContent = error.message;
  }
});

input.addEventListener("input", resetResults);
form.addEventListener("reset", resetResults);
document.querySelector("#example").addEventListener("click", () => {
  input.value = [
    "HTTP/2 200",
    "Content-Type: text/html; charset=utf-8",
    "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security: max-age=31536000",
    "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin",
  ].join("\n");
  form.requestSubmit();
});
