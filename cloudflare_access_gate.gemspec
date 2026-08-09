# frozen_string_literal: true

require_relative 'lib/cloudflare_access_gate/version'

Gem::Specification.new do |spec|
  spec.name     = 'cloudflare_access_gate'
  spec.version  = CloudflareAccessGate::VERSION
  spec.authors  = ['Homebot Infrastructure']
  spec.email    = ['engineering@homebot.ai']

  spec.summary  = 'Cloudflare Access JWT gate + audit logger Rack middleware.'
  spec.description = <<~DESC
    Rack middleware that gates a Sidekiq (or any Rack) dashboard behind
    Cloudflare Access: it validates the Cf-Access-Jwt-Assertion JWT against your
    team's JWKS, issuer, and audience (fail-closed) and audit-logs every request
    that gets through. No Rails or logging-library dependency at runtime.
  DESC
  spec.homepage = 'https://github.com/homebotapp/cloudflare_access_gate'
  spec.license  = 'MIT'

  spec.required_ruby_version = '>= 3.1'

  spec.metadata['homepage_uri']          = spec.homepage
  spec.metadata['changelog_uri']         = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['bug_tracker_uri']       = "#{spec.homepage}/issues"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files         = Dir['lib/**/*.rb'] + %w[README.md CHANGELOG.md LICENSE.txt SECURITY.md]
  spec.require_paths = ['lib']

  # `jwt` is the only runtime dependency. Logging goes through
  # CloudflareAccessGate::StructuredLogger, which uses SemanticLogger when the
  # host app has it loaded and the stdlib Logger otherwise.
  spec.add_dependency 'jwt', '~> 2'

  # `.protect` wires in ActionDispatch (actionpack) at runtime, but the Gate and
  # AuditLogger middlewares are plain Rack, so actionpack is intentionally NOT a
  # runtime dependency — only Rails hosts calling `.protect` need it.
  spec.add_development_dependency 'actionpack', '>= 6.0'
  spec.add_development_dependency 'rack', '>= 2.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 1.0'
  # Exercises the SemanticLogger branch of StructuredLogger.
  spec.add_development_dependency 'semantic_logger', '>= 4', '< 6'
  spec.add_development_dependency 'timecop', '~> 0.9'
  spec.add_development_dependency 'webmock', '~> 3.0'
end
