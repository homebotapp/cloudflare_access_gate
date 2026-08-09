# Contributing

Bug reports and pull requests are welcome.

**Security issues do not belong in the issue tracker** — see
[SECURITY.md](SECURITY.md) for how to report those privately.

## Getting set up

```sh
bundle install
bundle exec rake    # rspec + rubocop, the same thing CI runs
```

The gem targets Ruby 3.1+ and is tested against 3.1–3.4.

## Ground rules for changes

This is auth middleware, so a few constraints are non-negotiable:

- **Fail closed.** Any new failure path must deny the request. If you add a
  config option, the default must be the safe value, and a missing or blank
  value must not skip a check.
- **No new runtime dependencies** beyond `jwt` without a strong reason. In
  particular, don't reach for ActiveSupport helpers (`.blank?`, `.present?`) —
  `spec/no_rails_spec.rb` runs the middlewares in a subprocess where requiring
  Rails, ActiveSupport, and SemanticLogger raises, and it will fail.
- **Cover both directions.** A change to verification needs a spec proving the
  bad token is rejected, not just that the good one still passes.

## Pull requests

1. Fork and branch.
2. Add specs; keep `bundle exec rake` green.
3. Add a `CHANGELOG.md` entry under `## [Unreleased]`.
4. Don't bump `lib/cloudflare_access_gate/version.rb` — maintainers do that at
   release.

Small, focused PRs get reviewed fastest. If you're planning something large,
open an issue first so we can agree on the shape.
