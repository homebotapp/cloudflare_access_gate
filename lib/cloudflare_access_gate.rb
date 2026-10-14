# frozen_string_literal: true

require 'cloudflare_access_gate/version'
require 'cloudflare_access_gate/structured_logger'
require 'cloudflare_access_gate/jwks_cache'
require 'cloudflare_access_gate/verifier'
require 'cloudflare_access_gate/gate'
require 'cloudflare_access_gate/audit_logger'

# Rack middleware that gates a dashboard (typically Sidekiq::Web) behind
# Cloudflare Access, plus an audit logger for the requests that get through.
# See the README for the ENV contract and security notes.
module CloudflareAccessGate
  @installed = {}
  @install_mutex = Mutex.new

  class << self
    # Logger used by both middlewares. Assign anything that responds to
    # `debug`/`info`/`warn`/`error` — SemanticLogger, a stdlib `Logger`,
    # `Rails.logger`, and so on:
    #
    #   CloudflareAccessGate.logger = Rails.logger
    #
    # When left unset (`nil`), SemanticLogger is used if the host app has it
    # loaded (giving per-class named loggers and tagged output), and a stdlib
    # `Logger.new($stdout)` otherwise.
    attr_accessor :logger

    # Returns the logger to use for `name`, wrapped so structured payloads work
    # regardless of the underlying logging library.
    def logger_for(name)
      StructuredLogger.wrap(@logger || default_logger(name))
    end

    private

    def default_logger(name)
      return ::SemanticLogger[name] if defined?(::SemanticLogger)

      stdout_logger
    end

    def stdout_logger
      @stdout_logger ||= ::Logger.new($stdout)
    end
  end

  # Wire the full Cloudflare Access protection stack onto a Rack app in the
  # canonical order. Typically called on Sidekiq::Web from an initializer:
  #
  #   CloudflareAccessGate.protect(
  #     Sidekiq::Web,
  #     audience: ENV['CLOUDFLARE_ACCESS_SIDEKIQ_AUD'],
  #     session_key: '_myapp_sidekiq_session'
  #   )
  #
  # This installs, in order:
  #   1. Gate            - rejects requests without a valid Cf-Access JWT
  #   2. AuditLogger     - logs who accessed the dashboard
  #   3. ActionDispatch::Cookies
  #   4. ActionDispatch::Session::CookieStore(key: session_key)
  #
  # ActionDispatch (from Rails/actionpack) must be loaded before this is
  # called, so `.protect` is for Rails hosts only. Gate and AuditLogger
  # themselves are plain Rack and carry no Rails dependency — outside Rails,
  # install them directly with `app.use`.
  #
  # Extra keyword arguments are forwarded to Gate (e.g. `team_domain:`,
  # `jwks_stale_grace:`).
  #
  # Idempotent: the middleware stack is class-level, so re-calling would
  # otherwise re-append it. Returns the app.
  def self.protect(app, audience:, session_key:, **gate_options)
    @install_mutex.synchronize do
      return app if @installed[app]

      app.use Gate, **gate_options, audience: audience
      app.use AuditLogger
      app.use ActionDispatch::Cookies
      app.use ActionDispatch::Session::CookieStore, key: session_key

      @installed[app] = true
    end

    app
  end
end
