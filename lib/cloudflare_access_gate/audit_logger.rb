# frozen_string_literal: true

module CloudflareAccessGate
  # Rack middleware that audit-logs every request to the gated dashboard,
  # recording the HTTP method, path, Cloudflare-authenticated user email, and
  # response status. Install it behind Gate so only authorized requests are
  # logged.
  #
  # Like Gate, this is plain Rack: no Rails, ActiveSupport, or logging library is
  # required at runtime.
  class AuditLogger
    LOGGED_METHODS = %w[GET POST PUT PATCH DELETE].freeze

    DEFAULT_MESSAGE = 'Sidekiq dashboard access'
    DEFAULT_TAG_KEY = :sidekiq_user

    # Options:
    #   logger:   per-instance logger override
    #   message:  log message for each audited request
    #   tag_key:  SemanticLogger named-tag key for the authenticated user
    def initialize(app, options = {})
      @app = app
      @logger = options[:logger] && StructuredLogger.wrap(options[:logger])
      @message = options.fetch(:message, DEFAULT_MESSAGE)
      @tag_key = options.fetch(:tag_key, DEFAULT_TAG_KEY)
    end

    def call(env)
      request_method = env['REQUEST_METHOD']

      return @app.call(env) unless LOGGED_METHODS.include?(request_method)

      email = env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] || 'unknown'
      status = nil

      # Logged in an `ensure` so a raising request is still audited.
      logger.tagged(@tag_key => email) do
        response = @app.call(env)
        status = response.first
        response
      ensure
        logger.info(
          @message,
          method: request_method,
          path: env['PATH_INFO'],
          user: email,
          status: status
        )
      end
    end

    private

    def logger
      @logger ||= CloudflareAccessGate.logger_for('CloudflareAccessGate::AuditLogger')
    end
  end
end
