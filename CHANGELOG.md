# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-14

Lets a host app use the verified Access identity, not just the gate's
pass/deny. Everything 0.2.1 verified is verified the same way; the gate's
behavior and ENV contract are unchanged.

### Added

- `CloudflareAccessGate::Verifier`, extracted from `Gate`. `#verify(token)`
  returns the claims of a fully verified token (signature against the team
  JWKS, issuer, audience, expiry, required claims) or `nil`, with the same
  fail-closed rules the gate applies: a blank audience or team domain, an
  unavailable JWKS, or any decode failure yields `nil`. The JWKS cache lives on
  the instance, so hold one verifier per audience for the life of the process.
- `Gate` exposes the verified token's claims to the app behind it as
  `env['cloudflare_access.claims']` (`Gate::CLAIMS_ENV_KEY`). The key is absent
  when JWT validation is disabled, since nothing about the token was checked.
- `verifier:` option on `Gate`, forwarded by `.protect`, so a host app can share
  one `Verifier` (and its JWKS cache) between the gate and its own login code.

### Changed

- `Gate#audience` and `#team_domain` now read from its verifier.
  `Gate::DEFAULT_LEEWAY` and `Gate::REQUIRED_CLAIMS` remain as aliases of the
  `Verifier` constants.

## [0.2.1] - 2026-08-09

First release published to RubyGems. The library is unchanged from 0.2.0 — that
version was tagged in the repository but never pushed to rubygems.org, so 0.2.1
is the first version installable with `gem install cloudflare_access_gate`.

### Added
- A `Release` workflow that builds the gem and publishes it to RubyGems via
  [trusted publishing](https://guides.rubygems.org/trusted-publishing/) whenever
  a `v*` tag is pushed, so a release needs no long-lived API key on anyone's
  machine. It refuses to publish when the tag and `VERSION` disagree, since a
  yanked version number can never be re-pushed.

## [0.2.0] - 2026-08-05

Public-release preparation on top of 0.1.1. Everything 0.1.1 added is kept: the
`ensure`-logged audit record, `.protect` idempotency, the plain-Ruby blank
check, and the fail-closed flag specs.

### Security

- **Verify the `iss` claim.** Tokens are now checked against
  `https://<team>.cloudflareaccess.com`, so a valid Access JWT minted by a
  *different* Access team is rejected instead of accepted.
- **Deny when the team domain is unset**, as an explicit fail-closed check
  rather than a side effect of the JWKS fetch failing.
- **Require `exp`, `iss`, and `aud` to be present.** The `jwt` gem's `verify_*`
  options only check a claim when it exists, so a correctly signed token with the
  right issuer and audience but *no* `exp` was accepted indefinitely. Now passed
  as `required_claims`.
- **Reject an unusable JWKS.** A `{"keys": []}` response — or one whose entries
  carry no key type, e.g. `{"keys":[{}]}` — is treated as a failed fetch. The
  latter previously cached as good, evicting the last known-good key set and then
  failing every signature check for a full TTL instead of falling back to it.
- **Synchronize the JwksCache construction.** `JwksCache` guards its own fetches,
  but `Gate` memoized it with an unsynchronized `||=`, so concurrent cold-start
  requests could each build a separate cache and run a separate 6-second fetch —
  defeating the backoff this release added.

### Fixed

- **Rack 3 SPEC compliance.** The 403 response used a `Content-Type` header,
  which Rack 3 rejects outright (`Rack::Lint::LintError: uppercase character in
  header name`). Header names are now lowercase, valid on both Rack 2 and Rack 3.
  The response also carries an explicit `content-length`, and its headers hash is
  a fresh mutable hash per response, so downstream middleware can add to it.
  `spec/rack_compliance_spec.rb` runs every response through `Rack::Lint`, and CI
  exercises Rack 2.2 and 3.x across the whole Ruby matrix.

### Added

- Clock-drift leeway of 60s for `exp`/`nbf` (configurable via `leeway:`),
  matching the tolerance Cloudflare itself applies. Fixes spurious 403s from
  minor clock skew. (`iat` is deliberately not covered: ruby-jwt leaves
  `verify_iat` off and its `iat` check does not consume this leeway.)
- `CloudflareAccessGate::JwksCache`, extracted from `Gate`, with two new
  availability behaviors:
  - a 30-second backoff after a failed fetch, so a JWKS outage no longer queues
    every request behind its own (up to 6s) HTTP timeout while holding the cache
    mutex;
  - a staleness grace window (`jwks_stale_grace:`, default 300s) during which a
    previously-good key set is reused if a refresh fails. Set to `0` for strict
    behavior.
- `CloudflareAccessGate::StructuredLogger` and `CloudflareAccessGate.logger`, so
  any logger works: SemanticLogger gets native structured payloads and named
  tags, and everything else gets the payload appended as `key=value` pairs.
- `logger:` option on both middlewares; `message:` and `tag_key:` on
  `AuditLogger`; `team_domain:`/`leeway:`/`jwks_stale_grace:` on `Gate`.
- `.protect` forwards extra keyword arguments to `Gate`.
- `spec/no_rails_spec.rb`, which runs the middlewares in a subprocess where
  requiring Rails, ActiveSupport, or SemanticLogger raises — the 0.1.1 blank-check
  fix is now guarded against regression rather than asserted in prose.
- `SECURITY.md` with a private vulnerability reporting path, and
  `CONTRIBUTING.md`.
- CI pins `ruby/setup-ruby` to a commit SHA rather than the mutable `v1` tag,
  clearing the CodeQL unpinned-third-party-action finding.

### Changed (breaking)

- **Gem renamed** from `cloudflare-access-gate` to `cloudflare_access_gate`, so
  `require:` no longer has to be spelled out in a `Gemfile`. The library name and
  `CloudflareAccessGate` namespace are unchanged.
- **`semantic_logger` is no longer a runtime dependency** — it is used when the
  host app has it loaded and ignored otherwise, which supersedes 0.1.1's
  `>= 4, < 6` runtime bound (that bound now applies to the development
  dependency). `jwt` is the only runtime dependency.
- **`required_ruby_version` lowered back to `>= 3.1`** from 0.1.1's `>= 3.4`. A
  public gem shouldn't demand the newest Ruby, and CI now proves 3.1 works by
  testing the full 3.1-3.4 range instead of 3.4 alone.
- Removed the `allowed_push_host` gemspec pin to a private registry.
- Internal application names, ticket IDs, and the Access team slug are out of the
  README, CHANGELOG, gemspec, and specs ahead of the repository going public.

## [0.1.1] - 2026-07-24

### Fixed
- `Gate` no longer depends on ActiveSupport: the `.blank?` calls on the token,
  audience, and team domain are replaced with a plain-Ruby check, so the
  advertised "standalone / plain Rack, no Rails dependency" claim actually holds
  for a non-Rails consumer (previously raised `NoMethodError`).
- `AuditLogger` now emits the access line in an `ensure` block, so a request
  that raises (e.g. Redis down mid-POST) is still audited (status best-effort
  `nil`) before the error propagates — previously the record vanished exactly
  when it mattered.
- `.protect` is now idempotent: repeated calls for the same app (including
  a development route-reload) no longer re-append the class-level middleware
  stack. Returns the app.

### Changed
- `semantic_logger` dependency is bounded (`>= 4, < 6`) so a future major can't
  break consumers whose lockfile has resolved past the pinned revision.
- `required_ruby_version` raised to `>= 3.4` to match what CI actually tests
  (the RuboCop `TargetRubyVersion` and CI matrix are aligned at 3.4).

### Added
- Specs for the fail-closed flag semantics (non-`'false'` and unset both stay
  enabled), the team-domain-blank fail-closed path, the 403 response body /
  `Content-Type`, `.protect` idempotency + return value, and `ensure`-logging on
  a raising inner app.

### Docs
- Corrected the provenance: one consumer held the vendored copy; the other two
  migrated from HTTP Basic Auth / a Devise session.
- README: `github:` install shorthand, a per-app `session_key` example,
  `CLOUDFLARE_ACCESS_SIDEKIQ_AUD` in the ENV table, a
  local-dev (`ENABLE_CLOUDFLARE_GATE=false`) note, a `session_key` rationale, a
  Releasing section, and both wiring placements (initializer or inline routes).

## [0.1.0] - 2026-07-24

### Added
- Initial extraction of the Cloudflare Access Sidekiq gate middleware
  consolidated from three internal Rails applications.
- `CloudflareAccessGate::Gate` — Rack middleware that validates the
  `Cf-Access-Jwt-Assertion` header against the Cloudflare Access team JWKS and a
  configured audience. Fails closed: gate + JWT validation stay on unless a flag
  is explicitly set to `'false'`, and a blank audience or unavailable JWKS
  yields a 403. Hardened with JWKS HTTP timeouts, TLS peer verification, a
  mutex-guarded JWKS cache, and denial logging (path + user).
- `CloudflareAccessGate::AuditLogger` — Rack middleware that logs
  method/path/user/status for every dashboard request via SemanticLogger.
- `CloudflareAccessGate.protect(app, audience:, session_key:)` — installer
  helper that wires Gate, AuditLogger, `ActionDispatch::Cookies`, and
  `ActionDispatch::Session::CookieStore` onto a Rack app in the canonical order.

### Notes
- The `BLOCKED_METHODS` HTTP-method blocklist present in earlier copies was
  intentionally dropped and is not carried by this gem.
