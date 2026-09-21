#!/usr/bin/env node
// Verify a generated PAC (from `acp intercept pac` or the extension) by emulating Chrome's PAC
// helper functions and asserting routing decisions. Usage: node verify_pac.js <pac-file>
const fs = require("fs");
const pacPath = process.argv[2];
if (!pacPath) { console.error("usage: node verify_pac.js <pac-file>"); process.exit(2); }
let pac = fs.readFileSync(pacPath, "utf8");

// Chrome PAC host helpers (minimal, standard semantics).
function dnsDomainIs(host, domain) {
  return host.length >= domain.length && host.substring(host.length - domain.length) === domain;
}
function shExpMatch(str, pat) {
  const re = new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
  return re.test(str);
}
// Load FindProxyForURL from the PAC text.
const factory = new Function("dnsDomainIs", "shExpMatch", pac + "\nreturn FindProxyForURL;");
const FindProxyForURL = factory(dnsDomainIs, shExpMatch);

let fails = 0;
function check(host, expectProxy) {
  const r = FindProxyForURL("https://" + host + "/", host);
  const isProxy = r.startsWith("PROXY");
  const ok = isProxy === expectProxy;
  if (!ok) fails++;
  console.log(`  ${ok ? "ok " : "FAIL"}  ${host.padEnd(28)} -> ${r} (${expectProxy ? "expected PROXY" : "expected DIRECT"})`);
}

// Cases keyed to the sample rules file the caller writes.
const cases = JSON.parse(process.env.PAC_CASES || "[]");
for (const [host, expectProxy] of cases) check(host, expectProxy);
console.log(fails === 0 ? "PAC verification: PASS" : `PAC verification: ${fails} FAILURE(S)`);
process.exit(fails === 0 ? 0 : 3);
