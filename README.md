# cloudflare_access_gate

Rack middleware that gates a Sidekiq (or any Rack) dashboard behind
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/),
plus an audit logger for every request that gets through.

It **fails closed** and has exactly one runtime dependency
([`jwt`](https://github.com/jwt/ruby-jwt)) — no Rails, no ActiveSupport, and no
logging library required. It works on **Rack 2 and Rack 3**, and it doesn't even
require `rack` itself: it calls no Rack APIs, only the SPEC's `call(env)`
contract.

It ships two plain-Rack middlewares and one Rails installer helper:

- `CloudflareAccessGate::Gate` — validates the `Cf-Access-Jwt-Assertion` header
  (injected by the Cloudflare Access application in front of your host) against
  your Access team's JWKS, issuer, and audience. **Fails closed.**
- `CloudflareAccessGate::AuditLogger` — logs `method` / `path` / `user` /
  `status` for GET, POST, PUT, PATCH, and DELETE dashboard requests, in an
  `ensure` so the record is emitted even if the request raises.
- `CloudflareAccessGate.protect(app, audience:, session_key:)` — wires both
  middlewares plus the ActionDispatch cookie/session store onto a Rack app in
  the canonical order (Rails hosts only). Idempotent.

## Installation

```ruby
gem 'cloudflare_access_gate'
```

Or straight from git, pinned to a tag:

```ruby
gem 'cloudflare_access_gate', github: 'homebotapp/cloudflare_access_gate',
    tag: 'v0.2.1'
```

## Usage

### Rails + Sidekiq

Mount `Sidekiq::Web` **outside** your authenticated routes and register the gate
on it. Two placements are both valid — pick whichever your app already uses.

**A. Initializer** (e.g. `config/initializers/sidekiq_web.rb`), wired in an
`after_initialize` hook so the autoloader/eager-load have finished:

```ruby
require 'sidekiq/web'

Rails.application.config.after_initialize do
  CloudflareAccessGate.protect(
    Sidekiq::Web,
    audience: ENV.fetch('CLOUDFLARE_ACCESS_SIDEKIQ_AUD', nil),
    session_key: '_myapp_sidekiq_session'
  )
end
```

**B. Inline in `config/routes.rb`**, immediately before you `mount Sidekiq::Web`:

```ruby
CloudflareAccessGate.protect(
  Sidekiq::Web,
  audience: ENV.fetch('CLOUDFLARE_ACCESS_SIDEKIQ_AUD', nil),
  session_key: '_myapp_sidekiq_session'
)
mount Sidekiq::Web => '/sidekiq'
```

`.protect` installs, in order:

1. `CloudflareAccessGate::Gate` (with the given `audience`)
2. `CloudflareAccessGate::AuditLogger`
3. `ActionDispatch::Cookies`
4. `ActionDispatch::Session::CookieStore` (keyed by `session_key`)

It is **idempotent** per app: `Sidekiq::Web`'s middleware stack is class-level,
so calling `.protect` twice — or on a development route-reload — would otherwise
re-append the whole stack. Repeated calls for the same app are a no-op, and the
app is returned either way.

Extra keyword arguments are forwarded to `Gate`, so
`CloudflareAccessGate.protect(app, audience: …, session_key: …, jwks_stale_grace: 0)`
works.

`ActionDispatch` must already be loaded, so `.protect` is for Rails hosts.

### `session_key`

Pass a **unique** `session_key` per app so the Sidekiq dashboard's session
cookie doesn't collide with another app's cookie when several dashboards share a
parent domain.

The cookie/session pair isn't for the gate — the gate is stateless, since
Cloudflare Access appends `Cf-Access-Jwt-Assertion` to every proxied request.
It's for Sidekiq's own CSRF protection, which hard-fails any non-safe request
without a `rack.session`. An `api_only` Rails app has no Cookies/Session
middleware of its own, so without this pair every dashboard POST (retry, kill,
queue pause/delete) would raise.

### Any other Rack app

`Gate` and `AuditLogger` are plain Rack — install them directly:

```ruby
use CloudflareAccessGate::Gate, audience: ENV['CLOUDFLARE_ACCESS_AUD']
use CloudflareAccessGate::AuditLogger
```

## Configuration

### ENV contract

| Variable | Default | Effect |
| --- | --- | --- |
| `ENABLE_CLOUDFLARE_GATE` | `true` | Set to exactly `'false'` to disable the gate entirely. Any other value — including `'0'` — or unset keeps it **on**. |
| `ENABLE_CLOUDFLARE_JWT_VALIDATION` | `true` | Set to exactly `'false'` to skip signature/issuer/audience/expiry validation (header-presence check only). Any other value keeps validation **on**. |
| `CLOUDFLARE_ACCESS_TEAM_DOMAIN` | _(unset)_ | Your Access team slug, used to derive the issuer `https://<team>.cloudflareaccess.com` and fetch its `/cdn-cgi/access/certs`. If blank while validation is on, requests are denied. |
| `CLOUDFLARE_ACCESS_SIDEKIQ_AUD` | _(unset)_ | Conventional name for the Access application AUD tag. **Not read by the gem** — your app reads it and passes it as `audience:`. |

### Gate options

| Option | Default | Meaning |
| --- | --- | --- |
| `audience:` | _(none)_ | The Access application AUD tag. A blank audience denies every request rather than skipping audience verification. |
| `team_domain:` | `ENV['CLOUDFLARE_ACCESS_TEAM_DOMAIN']` | Access team slug. |
| `leeway:` | `60` | Clock-drift allowance in seconds for `exp`/`nbf`, matching the 60s Cloudflare itself allows. |
| `jwks_stale_grace:` | `300` | How long a previously-good JWKS may still be used when a refresh fails. `0` denies as soon as the cache expires. |
| `logger:` | _(global)_ | Per-instance logger override. |

### AuditLogger options

| Option | Default | Meaning |
| --- | --- | --- |
| `message:` | `'Sidekiq dashboard access'` | Log message for each audited request. |
| `tag_key:` | `:sidekiq_user` | SemanticLogger named-tag key for the authenticated user. |
| `logger:` | _(global)_ | Per-instance logger override. |

### Logging

Both middlewares log through `CloudflareAccessGate::StructuredLogger`, which
takes any logger you give it:

```ruby
CloudflareAccessGate.logger = Rails.logger
```

If you don't set one, [SemanticLogger](https://github.com/reidmorrison/semantic_logger)
is used when your app already has it loaded (giving per-class named loggers,
structured payloads, and a `sidekiq_user` named tag around each request), and a
stdlib `Logger.new($stdout)` otherwise. For non-SemanticLogger loggers the
structured payload is appended to the message as `key=value` pairs rather than
dropped, and tagging is skipped.

### Local development

There is no Cloudflare Access in front of your local dashboard, so no
`Cf-Access-Jwt-Assertion` header is present and the fail-closed gate returns
**403** for every `/sidekiq` request. To use the dashboard locally, set:

```sh
ENABLE_CLOUDFLARE_GATE=false
```

(Only the literal string `false` disables it.)

## Security behavior

### Fail-closed

- Missing/blank `Cf-Access-Jwt-Assertion` header → **403**.
- JWT validation on + blank audience → **403** (never verifies "no audience").
- JWT validation on + blank team domain → **403** (no issuer to verify against).
- JWKS endpoint unavailable, non-JSON, or containing no usable keys → **403**.
- Invalid signature, wrong issuer, wrong audience, expired token, or algorithm
  confusion (e.g. HS256 with the public key) → **403**.
- A token **missing** `exp`, `iss`, or `aud` → **403**. The `jwt` gem's
  `verify_*` options only check a claim that is present, so these are required
  explicitly; otherwise a correctly signed token with no `exp` would never
  expire.
- Flags are strict: only the literal string `'false'` disables the gate / JWT
  validation. Any other value — including `'0'` or an unset var — leaves them on.

### Hardening

- JWKS fetches use short open/read timeouts and `OpenSSL::SSL::VERIFY_PEER`.
- The JWKS cache is mutex-guarded and refreshed after a 10-minute TTL.
- A failed JWKS fetch starts a 30-second backoff, so a JWKS outage can't queue
  every request behind its own HTTP timeout.
- Denials are logged with the request path and the Cloudflare-authenticated user.

### The staleness trade-off

If a JWKS refresh fails, the last known-good key set is reused for up to
`jwks_stale_grace` seconds (default 300) past the cache TTL. Access signing keys
rotate on the order of weeks, so a few minutes of staleness is a much smaller
risk than locking every operator out of the dashboard during a transient
failure. If you would rather deny than serve stale keys, set
`jwks_stale_grace: 0`.

### What this middleware does *not* do

It verifies that a request carries a valid Access JWT for **your** application.
It does not implement per-user authorization — which identities may reach the
app is decided by your Cloudflare Access policy, not by this gem. It is also not
a substitute for keeping the origin unreachable except through Cloudflare; an
attacker who can reach your origin directly bypasses Access entirely, so pair
this with origin locking (Tunnel, mTLS, or IP allowlisting).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Rack compatibility

Supported on **Rack 2.x and Rack 3.x**, and on plain Rack-compatible servers with
no `rack` gem loaded at all — the middlewares implement `call(env)` and use
nothing from Rack's API.

Responses use **lowercase header names** (`content-type`, not `Content-Type`).
Rack 3 requires this — an uppercase header name is a `Rack::Lint::LintError`
there — and Rack 2 accepts it, since HTTP header names are case-insensitive. The
403 also carries an explicit `content-length`, and its headers hash is a fresh
mutable hash per response so downstream middleware can add to it.

`spec/rack_compliance_spec.rb` runs every response this gem produces through
`Rack::Lint`, the SPEC in executable form. CI runs it against both major Rack
versions across Ruby 3.1–3.4.

## Development

```sh
bundle install
bundle exec rspec      # test suite
bundle exec rubocop    # lint
bundle exec rake       # both (default task)
```

To test against a specific Rack major version, as CI does:

```sh
RACK_VERSION=2.2 bundle install && RACK_VERSION=2.2 bundle exec rspec
RACK_VERSION=3   bundle install && RACK_VERSION=3   bundle exec rspec
```

`spec/no_rails_spec.rb` runs the middlewares in a subprocess where requiring
Rails, ActiveSupport, or SemanticLogger raises, which is what keeps the
"no Rails dependency" claim honest. CI runs rspec on Ruby 3.1–3.4 against Rack
2.2 and 3.x, plus rubocop.

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Releasing

`.github/workflows/release.yml` publishes to RubyGems over
[trusted publishing](https://guides.rubygems.org/trusted-publishing/), so no API
key is stored in the repository or on a maintainer's machine.

1. Open a PR bumping `CloudflareAccessGate::VERSION` in
   `lib/cloudflare_access_gate/version.rb`, updating the version assertion in
   `spec/cloudflare_access_gate_spec.rb`, and adding a `CHANGELOG.md` entry.
   `main` is protected, so this can't be pushed directly.
2. Merge it once CI is green.
3. Create and push an annotated tag on the merge commit:
   `git tag -a vX.Y.Z -m "…" && git push origin vX.Y.Z`.
4. The Release workflow verifies the tag matches `VERSION`, builds the gem,
   pushes it to RubyGems, and creates the GitHub Release. A mismatch fails the
   job before anything is published — a yanked version number can never be
   reused.
5. For consumers pinned by git ref rather than the published gem, update the
   `tag:` in their `Gemfile` and re-resolve:
   `bundle update cloudflare_access_gate`.

Don't run `rake release` yourself: it pushes the release commit and tag straight
to `main`, which branch protection rejects. The workflow does invoke it, but
because the tag already exists when it runs, Bundler skips its source-control
push and goes straight to publishing.

## License

[MIT](LICENSE.txt) © Homebot, Inc.
