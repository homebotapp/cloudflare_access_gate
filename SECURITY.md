# Security Policy

## Supported versions

Security fixes are released for the latest minor version. Until 1.0, that means
the most recent `0.x` release.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report it privately through either channel:

- GitHub's [private vulnerability reporting](https://github.com/homebotapp/cloudflare_access_gate/security/advisories/new)
  (Security → Report a vulnerability), or
- email **engineering@homebot.ai** with `cloudflare_access_gate` in the subject.

Please include the affected version, a description of the impact, and enough
detail to reproduce — a failing spec or a minimal Rack app is ideal.

We aim to acknowledge a report within 3 business days and to ship a fix or share
a mitigation timeline within 30 days. We'll credit you in the advisory and
CHANGELOG unless you'd rather stay anonymous.

## Scope

In scope — anything that lets a request reach the protected app without a valid
Cloudflare Access JWT for the configured audience, for example:

- accepting a token with a wrong or absent signature, issuer, audience, or expiry
- a configuration or failure mode that opens the gate instead of closing it
- cache poisoning of the JWKS, or accepting keys from another Access team

Out of scope:

- Cloudflare Access policy misconfiguration (which identities are allowed is
  decided in your Access policy, not by this gem)
- an origin reachable without going through Cloudflare — see "What this
  middleware does *not* do" in the README
- setting `ENABLE_CLOUDFLARE_GATE=false` or `ENABLE_CLOUDFLARE_JWT_VALIDATION=false`,
  which are documented, deliberate off switches
- vulnerabilities in the `jwt` gem itself (report those to
  [ruby-jwt](https://github.com/jwt/ruby-jwt/security))
