# frozen_string_literal: true

require 'jwt'

module CloudflareAccessGate
  # Rack middleware that gates a dashboard (typically Sidekiq::Web) behind
  # Cloudflare Access. It reads the `Cf-Access-Jwt-Assertion` header injected by
  # the Cloudflare Access application in front of the host and, when JWT
  # validation is enabled, verifies the token's signature (against the team's
  # JWKS), issuer, audience, and expiry before letting the request through.
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
    # Clock drift allowance for exp/nbf, matching the 60s Cloudflare itself
    # allows when validating tokens. (`iat` is not verified: ruby-jwt leaves
    # verify_iat off by default and its iat check ignores this leeway.)
    DEFAULT_LEEWAY = 60 # seconds

    # `verify_*` options only check a claim when it is present, so a correctly
    # signed token that simply omits `exp` would otherwise never expire.
    REQUIRED_CLAIMS = %w[exp iss aud].freeze

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

    attr_reader :audience, :team_domain

    # Options:
    #   audience:         (required in practice) the Access application AUD tag
    #   team_domain:      Access team slug; defaults to ENV
    #   leeway:           clock drift allowance in seconds
    #   jwks_stale_grace: seconds a stale JWKS may be reused on refresh failure
    #   logger:           per-instance logger override
    #   clock:            callable returning monotonic seconds (for tests)
    def initialize(app, options = {})
      @app = app
      @audience = options[:audience]
      @team_domain = options.fetch(:team_domain) { ENV.fetch('CLOUDFLARE_ACCESS_TEAM_DOMAIN', nil) }
      @leeway = options.fetch(:leeway, DEFAULT_LEEWAY)
      @logger = options[:logger] && StructuredLogger.wrap(options[:logger])
      @jwks_cache_mutex = Mutex.new
      @jwks_options = {
        stale_grace: options.fetch(:jwks_stale_grace, JwksCache::DEFAULT_STALE_GRACE),
        clock: options.fetch(:clock, JwksCache::MONOTONIC_CLOCK)
      }
    end

    def call(env)
      return @app.call(env) unless self.class.enabled?

      token = env['HTTP_CF_ACCESS_JWT_ASSERTION']
      return forbidden('Missing access token', env) if blank?(token)

      return forbidden('Invalid access token', env) unless token_acceptable?(token)

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

    private

    # When JWT validation is switched off, the presence of the header (already
    # checked by the caller) is all that is required.
    def token_acceptable?(token)
      return true unless self.class.jwt_validation_enabled?

      !verify_token(token).nil?
    end

    # Returns the decoded payload, or nil if the token must be rejected.
    def verify_token(token)
      return nil unless verifiable?

      jwks = jwks_cache.fetch
      return nil unless jwks

      decode(token, jwks)
    rescue JWT::DecodeError => e
      logger.warn('Cloudflare Access JWT verification failed', error: e.message, error_class: e.class.name)
      nil
    end

    def decode(token, jwks)
      JWT.decode(
        token,
        nil,
        true,
        algorithms: ['RS256'],
        jwks: jwks,
        aud: audience,
        verify_aud: true,
        iss: issuer,
        verify_iss: true,
        verify_expiration: true,
        required_claims: REQUIRED_CLAIMS,
        leeway: @leeway
      ).first
    end

    # Both of these must be configured for verification to mean anything, so a
    # blank value denies rather than silently skipping a check.
    def verifiable?
      # A nil/blank audience makes the jwt gem skip aud verification, which would
      # let any valid Cloudflare Access JWT (from any app) through.
      if blank?(audience)
        logger.error('Cloudflare Access JWT not verified: audience not configured')
        return false
      end

      # The issuer and the JWKS URL are both derived from the team domain.
      if blank?(team_domain)
        logger.error('Cloudflare Access JWT not verified: CLOUDFLARE_ACCESS_TEAM_DOMAIN unset')
        return false
      end

      true
    end

    def issuer
      "https://#{team_domain}.cloudflareaccess.com"
    end

    # Synchronized: JwksCache guards its own fetches, but an unsynchronized
    # `||=` here lets concurrent cold-start requests each build their own cache
    # and each run a separate fetch, which is what the backoff exists to prevent.
    def jwks_cache
      @jwks_cache_mutex.synchronize do
        @jwks_cache ||= JwksCache.new(
          certs_url: "#{issuer}/cdn-cgi/access/certs",
          logger: logger,
          **@jwks_options
        )
      end
    end

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
