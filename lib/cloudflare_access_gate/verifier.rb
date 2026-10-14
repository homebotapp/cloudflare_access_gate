# frozen_string_literal: true

require 'jwt'

module CloudflareAccessGate
  # Verifies a Cloudflare Access application token (the `Cf-Access-Jwt-Assertion`
  # header) against the team's JWKS, issuer, audience, and expiry, and returns
  # its claims. `Gate` uses one of these to decide whether a request passes;
  # host apps can use one directly to establish identity from a token — for
  # example, to log a user in by the verified `email` claim.
  #
  # Everything is fail-closed: a blank audience or team domain, an unavailable
  # JWKS, or any decode failure returns nil rather than a partially verified
  # payload. Only the claims of a fully verified token are ever returned.
  #
  # Hold one instance per audience for the life of the process: the JWKS cache
  # (TTL, error backoff, staleness grace) lives on the instance, so a verifier
  # built per request would fetch the JWKS per request.
  #
  # This class is plain Ruby: no Rails, ActiveSupport, or logging library is
  # required at runtime.
  class Verifier
    # Clock drift allowance for exp/nbf, matching the 60s Cloudflare itself
    # allows when validating tokens. (`iat` is not verified: ruby-jwt leaves
    # verify_iat off by default and its iat check ignores this leeway.)
    DEFAULT_LEEWAY = 60 # seconds

    # `verify_*` options only check a claim when it is present, so a correctly
    # signed token that simply omits `exp` would otherwise never expire.
    REQUIRED_CLAIMS = %w[exp iss aud].freeze

    attr_reader :audience, :team_domain

    # Options:
    #   audience:         (required in practice) the Access application AUD tag
    #   team_domain:      Access team slug; defaults to ENV
    #   leeway:           clock drift allowance in seconds
    #   jwks_stale_grace: seconds a stale JWKS may be reused on refresh failure
    #   logger:           per-instance logger override
    #   clock:            callable returning monotonic seconds (for tests)
    def initialize(audience:, **options)
      @audience = audience
      @team_domain = options.fetch(:team_domain) { ENV.fetch('CLOUDFLARE_ACCESS_TEAM_DOMAIN', nil) }
      @leeway = options.fetch(:leeway, DEFAULT_LEEWAY)
      @logger = options[:logger] && StructuredLogger.wrap(options[:logger])
      @jwks_cache_mutex = Mutex.new
      @jwks_options = {
        stale_grace: options.fetch(:jwks_stale_grace, JwksCache::DEFAULT_STALE_GRACE),
        clock: options.fetch(:clock, JwksCache::MONOTONIC_CLOCK)
      }
    end

    # Returns the token's claims as a Hash, or nil if the token must be
    # rejected for any reason.
    def verify(token)
      return nil if blank?(token)
      return nil unless verifiable?

      jwks = jwks_cache.fetch
      return nil unless jwks

      decode(token, jwks)
    rescue JWT::DecodeError => e
      logger.warn('Cloudflare Access JWT verification failed', error: e.message, error_class: e.class.name)
      nil
    end

    def issuer
      "https://#{team_domain}.cloudflareaccess.com"
    end

    private

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

    # Stands in for ActiveSupport's `Object#blank?` so the class works in a
    # plain Rack app with no Rails loaded.
    def blank?(value)
      value.nil? || value.to_s.strip.empty?
    end

    def logger
      @logger ||= CloudflareAccessGate.logger_for('CloudflareAccessGate::Verifier')
    end
  end
end
