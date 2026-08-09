# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'

module CloudflareAccessGate
  # Fetches and caches the Cloudflare Access team's JWKS (public signing keys).
  #
  # `#fetch` returns a usable key set or nil; nil means the caller must deny the
  # request. Three behaviors matter for a gate that has to stay both closed and
  # available:
  #
  # * **TTL** — a good key set is served from memory for CACHE_TTL seconds.
  # * **Error backoff** — fetches happen under a mutex, so without a cooldown
  #   every request during a JWKS outage would queue behind its own (up to 6s)
  #   HTTP timeout, hanging the dashboard. After a failure, Cloudflare isn't
  #   contacted again for ERROR_BACKOFF seconds.
  # * **Staleness grace** — if a refresh fails, the last known-good key set is
  #   reused for up to `stale_grace` seconds past the TTL. Access signing keys
  #   rotate on the order of weeks, so a few minutes of staleness is a far
  #   smaller risk than locking every operator out during a transient failure.
  #   Pass `stale_grace: 0` for strict behavior.
  class JwksCache
    CACHE_TTL = 600 # seconds a successfully fetched JWKS is served as fresh
    ERROR_BACKOFF = 30 # seconds to wait after a failed fetch before retrying
    DEFAULT_STALE_GRACE = 300 # seconds a stale JWKS may be reused past the TTL
    HTTP_OPEN_TIMEOUT = 3 # seconds
    HTTP_READ_TIMEOUT = 3 # seconds

    MONOTONIC_CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

    def initialize(certs_url:, logger:, stale_grace: DEFAULT_STALE_GRACE, clock: MONOTONIC_CLOCK)
      @certs_url = certs_url
      @logger = logger
      @stale_grace = stale_grace
      @clock = clock

      @jwks = nil
      @fetched_at = nil
      @failed_at = nil
      @mutex = Mutex.new
    end

    # Returns the JWKS to verify against, or nil if none can be obtained.
    def fetch
      @mutex.synchronize do
        return @jwks if fresh?
        return stale if backing_off?

        jwks = request
        return remember(jwks) if jwks

        @failed_at = now
        stale
      end
    end

    private

    attr_reader :logger

    def remember(jwks)
      @jwks = jwks
      @fetched_at = now
      @failed_at = nil
      @jwks
    end

    def fresh?
      !@jwks.nil? && !@fetched_at.nil? && (now - @fetched_at) < CACHE_TTL
    end

    # True while the JWKS endpoint is in its post-failure cooldown.
    def backing_off?
      !@failed_at.nil? && (now - @failed_at) < ERROR_BACKOFF
    end

    # The last known-good JWKS, if it is still inside the staleness grace window.
    def stale
      return nil if @jwks.nil? || @fetched_at.nil?

      age = now - @fetched_at
      if age > (CACHE_TTL + @stale_grace)
        logger.error('Cloudflare JWKS stale beyond grace period; denying requests', age_seconds: age.round)
        return nil
      end

      logger.warn('Serving stale Cloudflare JWKS after refresh failure', age_seconds: age.round)
      @jwks
    end

    # Returns the parsed JWKS on success, nil on any failure.
    def request
      uri = URI(@certs_url)
      response = http_get(uri)

      unless response.is_a?(Net::HTTPSuccess)
        logger.error('Cloudflare JWKS fetch failed', http_status: response&.code)
        return nil
      end

      parse(response.body)
    rescue StandardError => e
      logger.error('Failed to fetch Cloudflare JWKS', error: e.message, error_class: e.class.name)
      nil
    end

    def http_get(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.open_timeout = HTTP_OPEN_TIMEOUT
      http.read_timeout = HTTP_READ_TIMEOUT
      http.get(uri.request_uri)
    end

    def parse(body)
      jwks = JSON.parse(body)
      keys = jwks.is_a?(Hash) ? jwks['keys'] : nil

      # A key set that is empty — or whose entries carry no key type — would be
      # cached as good, discarding the last known-good set and then failing every
      # signature check for a full TTL. Treat it as a failed fetch instead, so the
      # staleness grace window can do its job.
      unless keys.is_a?(Array) && keys.any? { |key| usable_key?(key) }
        logger.error('Cloudflare JWKS response contained no usable keys')
        return nil
      end

      jwks
    rescue JSON::ParserError => e
      logger.error('Cloudflare JWKS response was not valid JSON', error: e.message)
      nil
    end

    # Minimum bar for a JWKS entry the jwt gem could actually verify against.
    def usable_key?(key)
      key.is_a?(Hash) && !key['kty'].to_s.strip.empty?
    end

    def now
      @clock.call
    end
  end
end
