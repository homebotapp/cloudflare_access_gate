# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CloudflareAccessGate::AuditLogger do
  let(:inner_app) { ->(_env) { [200, { 'content-type' => 'text/plain' }, ['OK']] } }
  let(:middleware) { described_class.new(inner_app, logger: logger) }

  # A real SemanticLogger, not a double: StructuredLogger detects SemanticLogger
  # by class, and a verifying double is not an instance of it.
  let(:logger) { SemanticLogger['audit-logger-spec'] }

  describe '#call' do
    before { allow(logger).to receive(:info) }

    it 'logs GET requests with user email' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'

      status, = middleware.call(env)

      expect(status).to eq(200)
      expect(logger).to have_received(:info).with(
        'Sidekiq dashboard access',
        { method: 'GET', path: '/sidekiq', user: 'admin@example.com', status: 200 }
      )
    end

    it 'logs POST requests' do
      env = Rack::MockRequest.env_for('/sidekiq/queues/default', method: 'POST')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'

      middleware.call(env)

      expect(logger).to have_received(:info).with(
        'Sidekiq dashboard access',
        { method: 'POST', path: '/sidekiq/queues/default', user: 'admin@example.com', status: 200 }
      )
    end

    it 'logs DELETE requests' do
      env = Rack::MockRequest.env_for('/sidekiq/queues/default', method: 'DELETE')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'

      middleware.call(env)

      expect(logger).to have_received(:info).with(
        'Sidekiq dashboard access',
        { method: 'DELETE', path: '/sidekiq/queues/default', user: 'admin@example.com', status: 200 }
      )
    end

    it 'uses "unknown" when email header is absent' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')

      middleware.call(env)

      expect(logger).to have_received(:info).with(
        'Sidekiq dashboard access',
        { method: 'GET', path: '/sidekiq', user: 'unknown', status: 200 }
      )
    end

    it 'skips logging for HEAD requests' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'HEAD')

      status, = middleware.call(env)

      expect(status).to eq(200)
      expect(logger).not_to have_received(:info)
    end

    it 'passes through to the inner app' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')
      status, _headers, body = middleware.call(env)

      expect(status).to eq(200)
      expect(body).to eq(['OK'])
    end

    it 'logs the actual response status, not a hardcoded 200' do
      app = ->(_env) { [503, {}, ['x']] }
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')

      described_class.new(app, logger: logger).call(env)

      expect(logger).to have_received(:info).with('Sidekiq dashboard access', hash_including(status: 503))
    end

    it 'still logs the access line when the inner app raises, then re-raises' do
      boom = ->(_env) { raise 'Redis down' }
      env = Rack::MockRequest.env_for('/sidekiq/queues/default', method: 'POST')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'

      expect { described_class.new(boom, logger: logger).call(env) }.to raise_error('Redis down')

      expect(logger).to have_received(:info).with(
        'Sidekiq dashboard access',
        { method: 'POST', path: '/sidekiq/queues/default', user: 'admin@example.com', status: nil }
      )
    end

    it 'uses the globally configured logger when no override is given' do
      CloudflareAccessGate.logger = logger
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')

      described_class.new(inner_app).call(env)

      expect(logger).to have_received(:info).with('Sidekiq dashboard access', hash_including(path: '/sidekiq'))
    end

    it 'accepts a custom log message' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')

      described_class.new(inner_app, logger: logger, message: 'Dashboard access').call(env)

      expect(logger).to have_received(:info).with('Dashboard access', hash_including(path: '/sidekiq'))
    end
  end

  describe 'tagging' do
    def tags_seen_by_inner_app(**options)
      env = Rack::MockRequest.env_for('/sidekiq', method: 'POST')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'
      seen = nil
      app = lambda do |_env|
        seen = SemanticLogger.named_tags
        [200, {}, ['OK']]
      end

      allow(logger).to receive(:info)
      described_class.new(app, logger: logger, **options).call(env)
      seen
    end

    it 'tags log lines emitted inside the request with the authenticated user' do
      expect(tags_seen_by_inner_app).to include(sidekiq_user: 'admin@example.com')
    end

    it 'accepts a custom tag key' do
      expect(tags_seen_by_inner_app(tag_key: :dashboard_user))
        .to include(dashboard_user: 'admin@example.com')
    end
  end

  describe 'with a plain stdlib Logger' do
    let(:io) { StringIO.new }
    let(:logger) { Logger.new(io) }

    it 'flattens the payload into the message instead of raising' do
      env = Rack::MockRequest.env_for('/sidekiq', method: 'GET')
      env['HTTP_CF_ACCESS_AUTHENTICATED_USER_EMAIL'] = 'admin@example.com'

      status, = middleware.call(env)

      expect(status).to eq(200)
      expect(io.string).to include('Sidekiq dashboard access')
      expect(io.string).to include('user="admin@example.com"')
      expect(io.string).to include('status=200')
    end

    it 'still audits a raising request without a tagging-capable logger' do
      boom = ->(_env) { raise 'Redis down' }
      env = Rack::MockRequest.env_for('/sidekiq', method: 'POST')

      expect { described_class.new(boom, logger: logger).call(env) }.to raise_error('Redis down')

      expect(io.string).to include('Sidekiq dashboard access')
      expect(io.string).to include('status=nil')
    end
  end
end
