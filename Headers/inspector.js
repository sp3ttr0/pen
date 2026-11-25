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
    headers.get(key).push(value.trim().toLowerCase());
  }
  if (!headers.size) throw new Error("Paste at least one response header to begin.");
  return headers;
}

function inspect(headers) {
  const values = name => headers.get(name.toLowerCase()) ?? [];
  const has = (name, value) => values(name).includes(value);
  const csp = values("Content-Security-Policy");
  const framing = csp.some(policy => /(?:^|;)\s*frame-ancestors\s+[^;\s]/.test(policy));
  const checks = [
    ["Content-Security-Policy", csp.some(Boolean), "Limits where the browser can load resources from. Review the enforced directives for your application. A report-only policy does not enforce restrictions."],
    ["Framing protection", framing || has("X-Frame-Options", "deny") || has("X-Frame-Options", "sameorigin"), "Use CSP frame-ancestors 'none' if the page should never be embedded, or specify the origins that need to embed it."],
    ["Strict-Transport-Security", values("Strict-Transport-Security").some(value => /(?:^|;)\s*max-age\s*=\s*0*[1-9][0-9]*\s*(?:;|$)/.test(value)), "Use a positive max-age on HTTPS responses. Enable includeSubDomains only when all subdomains are ready for HTTPS."],
    ["X-Content-Type-Options", has("X-Content-Type-Options", "nosniff"), "Set nosniff and serve resources with the correct Content-Type."],
    ["Referrer-Policy", /^(no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)$/.test(values("Referrer-Policy").join(",").split(",").at(-1).trim()), "Consider strict-origin-when-cross-origin or no-referrer, depending on how much referrer information the site needs to share."],
    ["Cross-Origin-Opener-Policy", has("Cross-Origin-Opener-Policy", "same-origin"), "Consider same-origin for strict opener isolation. Check compatibility with sign-in and payment popups."],
  ];
  return checks.map(([name, detected, guidance]) => ({ name, detected, guidance }));
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
    for (const { name, detected, guidance } of checks) {
      const card = document.createElement("article");
      card.className = "finding";
      const heading = document.createElement("h3");
      heading.textContent = name;
      const state = document.createElement("p");
      state.className = "state";
      state.textContent = detected ? "Setting detected" : "Review recommended";
      const detail = document.createElement("p");
      detail.textContent = guidance;
      card.append(heading, state, detail);
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
