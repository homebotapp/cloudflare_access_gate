# frozen_string_literal: true

module CloudflareAccessGate
  # Rack middleware that gates a dashboard (typically Sidekiq::Web) behind
  # Cloudflare Access. It reads the `Cf-Access-Jwt-Assertion` header injected by
  # the Cloudflare Access application in front of the host and, when JWT
  # validation is enabled, verifies the token (see `Verifier`) before letting
  # the request through. The verified claims are exposed to the app as
  # `env['cloudflare_access.claims']`.
  #
  # Everything is fail-closed: the gate stays on and rejects requests unless a
  # flag is explicitly set to the string 'false', and a missing audience, missing
  # team domain, or unavailable JWKS results in a 403 rather than an open door.
  #
  # ENV contract:
  #   ENABLE_CLOUDFLARE_GATE            - 'false' disables the gate entirely
  #   ENABLE_CLOUDFLARE_JWT_VALIDATION  - 'false' skips signature/iss/aud checks
  #   CLOUDFLARE_ACCESS_TEAM_DOMAIN     - your Cloudflare Access team slug
  # The audience is passed as a constructor option, not read from ENV.
  #
  # This class is plain Rack: no Rails, ActiveSupport, or logging library is
  # required at runtime.
  class Gate
    DEFAULT_LEEWAY = Verifier::DEFAULT_LEEWAY
    REQUIRED_CLAIMS = Verifier::REQUIRED_CLAIMS

    # Rack env key under which the verified token's claims are stored for the
    # app behind the gate. Absent when JWT validation is disabled, since then
    # nothing about the token has been checked.
    CLAIMS_ENV_KEY = 'cloudflare_access.claims'

    FORBIDDEN_BODY = 'Forbidden'

    # Header names are lowercase because the Rack 3 SPEC requires it ("uppercase
    # character in header name" is a Rack::Lint error there). Rack 2 accepts
    # lowercase too — HTTP header names are case-insensitive — so one spelling
    # is correct on both. `content-length` is set explicitly so the response is
    # complete for servers that don't add it.
    FORBIDDEN_HEADERS = {
      'content-type' => 'text/plain',
      'content-length' => FORBIDDEN_BODY.bytesize.to_s
    }.freeze

    VERIFIER_OPTIONS = %i[audience team_domain leeway jwks_stale_grace logger clock].freeze

    attr_reader :verifier

    # Options:
    #   verifier:         a Verifier to share with the host app; when given, the
    #                     options below are ignored in favour of its configuration
    #   audience:         (required in practice) the Access application AUD tag
    #   team_domain:      Access team slug; defaults to ENV
    #   leeway:           clock drift allowance in seconds
    #   jwks_stale_grace: seconds a stale JWKS may be reused on refresh failure
    #   logger:           per-instance logger override
    #   clock:            callable returning monotonic seconds (for tests)
    def initialize(app, options = {})
      @app = app
      @logger = options[:logger] && StructuredLogger.wrap(options[:logger])
      @verifier = options.fetch(:verifier) { Verifier.new(**options.slice(*VERIFIER_OPTIONS)) }
    end

    def call(env)
      return @app.call(env) unless self.class.enabled?

      token = env['HTTP_CF_ACCESS_JWT_ASSERTION']
      return forbidden('Missing access token', env) if blank?(token)

      if self.class.jwt_validation_enabled?
        claims = verifier.verify(token)
        return forbidden('Invalid access token', env) unless claims

        env[CLAIMS_ENV_KEY] = claims
      end

      @app.call(env)
    end

    # Fail closed: the gate stays ON unless explicitly disabled with 'false'.
    def self.enabled?
      ENV.fetch('ENABLE_CLOUDFLARE_GATE', 'true') != 'false'
    end

    # Fail closed: JWT validation stays ON unless explicitly disabled with 'false'.
    def self.jwt_validation_enabled?
      ENV.fetch('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true') != 'false'
    end

    def audience
      verifier.audience
    end

    def team_domain
      verifier.team_domain
    end

    private

    def forbidden(message, env)
      logger.warn('Cloudflare Access gate denied request',
                  reason: message,
                  path: env['PATH_INFO'],
                  user: env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'])
      [403, FORBIDDEN_HEADERS.dup, [FORBIDDEN_BODY]]
    end

    # Stands in for ActiveSupport's `Object#blank?` so the middleware works in a
    # plain Rack app with no Rails loaded.
    def blank?(value)
      value.nil? || value.to_s.strip.empty?
    end

    def logger
      @logger ||= CloudflareAccessGate.logger_for('CloudflareAccessGate::Gate')
    end
  end
end
