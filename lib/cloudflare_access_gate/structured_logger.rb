# frozen_string_literal: true

require 'logger'

module CloudflareAccessGate
  # Thin adapter that lets this gem emit structured key/value log payloads
  # without depending on any particular logging library.
  #
  # SemanticLogger accepts a payload natively (`logger.warn('msg', key: 'v')`);
  # the stdlib `Logger`, `Rails.logger`, lograge, and friends do not. This
  # wrapper detects a SemanticLogger target and passes the payload through,
  # and otherwise appends a `key=value` suffix to the message so no log data is
  # lost.
  #
  # Wrap any logger-ish object: it only needs to respond to the standard
  # `debug`/`info`/`warn`/`error` severity methods.
  class StructuredLogger
    LEVELS = %i[debug info warn error].freeze

    attr_reader :target

    # Wraps `logger` unless it is already wrapped.
    def self.wrap(logger)
      logger.is_a?(self) ? logger : new(logger)
    end

    def initialize(target)
      @target = target
    end

    LEVELS.each do |level|
      define_method(level) do |message, **payload|
        emit(level, message, payload)
      end
    end

    # Attaches `tags` to every log line emitted inside the block.
    #
    # Only SemanticLogger supports this; for every other logger the block is
    # simply yielded (the same key/values are still emitted in the payload of
    # the log line itself, so nothing is silently dropped).
    def tagged(**tags, &block)
      return block.call if tags.empty? || !structured?

      target.tagged(**tags, &block)
    end

    private

    def emit(level, message, payload)
      if structured?
        target.public_send(level, message, payload)
      else
        target.public_send(level, merged_message(message, payload))
      end
    end

    def structured?
      defined?(::SemanticLogger::Base) && target.is_a?(::SemanticLogger::Base)
    end

    def merged_message(message, payload)
      return message if payload.empty?

      "#{message} (#{payload.map { |key, value| "#{key}=#{value.inspect}" }.join(' ')})"
    end
  end
end
