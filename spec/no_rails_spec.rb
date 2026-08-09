# frozen_string_literal: true

require 'spec_helper'
require 'open3'

# Regression guard for the gem's central compatibility claim: Gate and
# AuditLogger are plain Rack and need neither Rails/ActiveSupport nor a logging
# library. Asserting that from the main suite is impossible — RSpec itself loads
# ActiveSupport (via actionpack, which `.protect` needs), so a stray `.blank?`
# would keep working here and only blow up in a real non-Rails app.
#
# So this runs the middlewares in a subprocess where `require` of Rails,
# ActiveSupport, and SemanticLogger is forced to fail.
RSpec.describe 'running without Rails or SemanticLogger' do
  # Fails any require of the libraries the gem must not depend on, so a
  # transitive load surfaces as a test failure instead of silently satisfying it.
  def forbid_requires
    <<~RUBY
      FORBIDDEN = %w[rails active_support activesupport action_dispatch actionpack semantic_logger].freeze
      module Kernel
        alias_method :require_without_guard, :require
        def require(name)
          if FORBIDDEN.any? { |f| name.to_s == f || name.to_s.start_with?("\#{f}/") }
            raise LoadError, "forbidden require: \#{name}"
          end

          require_without_guard(name)
        end
      end
    RUBY
  end

  def run_in_clean_ruby(body)
    script = "#{forbid_requires}\nrequire 'cloudflare_access_gate'\n#{body}"
    Open3.capture3(RbConfig.ruby, '-I', File.expand_path('../lib', __dir__), '-e', script)
  end

  it 'loads the gem, denies an unauthenticated request, and audit-logs an allowed one' do
    stdout, stderr, status = run_in_clean_ruby(<<~RUBY)
      require 'stringio'

      log = StringIO.new
      CloudflareAccessGate.logger = Logger.new(log)

      app = ->(_env) { [200, {}, ['OK']] }
      stack = CloudflareAccessGate::AuditLogger.new(
        CloudflareAccessGate::Gate.new(app, audience: 'aud', team_domain: 'example')
      )

      # No JWT header: the gate must deny before any JWKS fetch is attempted.
      denied, = stack.call({ 'REQUEST_METHOD' => 'GET', 'PATH_INFO' => '/sidekiq' })
      raise "expected 403, got \#{denied}" unless denied == 403

      # Gate disabled: the audit logger still runs on the way through.
      ENV['ENABLE_CLOUDFLARE_GATE'] = 'false'
      allowed, = stack.call({ 'REQUEST_METHOD' => 'GET', 'PATH_INFO' => '/sidekiq' })
      raise "expected 200, got \#{allowed}" unless allowed == 200

      raise 'audit log line missing' unless log.string.include?('Sidekiq dashboard access')
      raise 'ActiveSupport was loaded' if defined?(ActiveSupport)
      raise 'SemanticLogger was loaded' if defined?(SemanticLogger)

      puts 'OK'
    RUBY

    expect(status).to be_success, "exited #{status.exitstatus}\nstdout: #{stdout}\nstderr: #{stderr}"
    expect(stdout).to include('OK')
  end
end
