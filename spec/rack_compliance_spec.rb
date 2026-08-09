# frozen_string_literal: true

require 'spec_helper'
require 'rack/lint'

# Rack 2 and Rack 3 disagree about response headers: Rack 3 requires lowercase
# header names and raises `Rack::Lint::LintError: uppercase character in header
# name` otherwise, while Rack 2 is indifferent. Rack::Lint is the SPEC made
# executable, so every response this gem generates is run through it here.
#
# CI runs this file against both major versions (see RACK_VERSION in the
# Gemfile); locally it validates whichever Rack is bundled.
RSpec.describe "Rack SPEC compliance (Rack #{Rack.release})" do
  let(:inner_app) { ->(_env) { [200, { 'content-type' => 'text/plain' }, ['OK']] } }
  let(:env) { Rack::MockRequest.env_for('/sidekiq') }

  # Rack::Lint validates both the request it passes down and the response that
  # comes back, so a violation anywhere in the stack raises.
  def linted(app)
    Rack::Lint.new(app)
  end

  before do
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_GATE', 'true').and_return('true')
    allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true').and_return('false')
  end

  describe CloudflareAccessGate::Gate do
    let(:gate) { described_class.new(inner_app, audience: 'aud', team_domain: 'example') }

    it 'produces a SPEC-compliant response when it denies a request' do
      status, headers, = linted(gate).call(env)

      expect(status).to eq(403)
      expect(headers['content-type']).to eq('text/plain')
    end

    it 'produces a SPEC-compliant response when it lets a request through' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'token'

      status, = linted(gate).call(env)

      expect(status).to eq(200)
    end

    it 'uses only lowercase header names, as Rack 3 requires' do
      _status, headers, = gate.call(env)

      expect(headers.keys).to all(be_a(String))
      expect(headers.keys).to all(satisfy { |key| key == key.downcase })
    end

    it 'returns a mutable headers hash so downstream middleware can add to it' do
      _status, headers, = gate.call(env)

      expect { headers['set-cookie'] = 'a=b' }.not_to raise_error
    end

    it 'does not share one headers hash between responses' do
      _status, first, = gate.call(env)
      _status, second, = gate.call(Rack::MockRequest.env_for('/sidekiq'))
      first['x-mutated'] = '1'

      expect(second).not_to have_key('x-mutated')
    end

    it 'declares a content-length matching the body it returns' do
      _status, headers, body = gate.call(env)

      expect(headers['content-length'].to_i).to eq(body.sum(&:bytesize))
    end
  end

  describe CloudflareAccessGate::AuditLogger do
    it 'passes the inner response through unchanged and stays SPEC-compliant' do
      middleware = described_class.new(inner_app, logger: Logger.new(StringIO.new))

      status, headers, body = linted(middleware).call(env)

      expect(status).to eq(200)
      expect(headers['content-type']).to eq('text/plain')
      expect(body.to_enum(:each).to_a).to eq(['OK'])
    end
  end

  describe 'the full middleware stack' do
    it 'is SPEC-compliant end to end on a denied request' do
      stack = CloudflareAccessGate::AuditLogger.new(
        CloudflareAccessGate::Gate.new(inner_app, audience: 'aud', team_domain: 'example'),
        logger: Logger.new(StringIO.new)
      )

      status, = linted(stack).call(env)

      expect(status).to eq(403)
    end
  end
end
