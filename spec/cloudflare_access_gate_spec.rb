# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CloudflareAccessGate do
  it 'has a version number' do
    expect(CloudflareAccessGate::VERSION).to eq('0.2.1')
  end

  describe '.protect' do
    let(:app) { spy('rack app') }

    it 'installs the gate, audit logger, cookies, and session store in order' do
      described_class.protect(app, audience: 'sidekiq-aud-tag', session_key: '_myapp_sidekiq_session')

      expect(app).to have_received(:use).with(CloudflareAccessGate::Gate, audience: 'sidekiq-aud-tag').ordered
      expect(app).to have_received(:use).with(CloudflareAccessGate::AuditLogger).ordered
      expect(app).to have_received(:use).with(ActionDispatch::Cookies).ordered
      expect(app).to have_received(:use)
        .with(ActionDispatch::Session::CookieStore, key: '_myapp_sidekiq_session').ordered
    end

    it 'forwards extra options to the gate' do
      described_class.protect(app, audience: 'aud', session_key: '_s', team_domain: 'example', jwks_stale_grace: 0)

      expect(app).to have_received(:use)
        .with(CloudflareAccessGate::Gate, audience: 'aud', team_domain: 'example', jwks_stale_grace: 0)
    end

    it 'returns the app' do
      expect(described_class.protect(app, audience: 'aud', session_key: '_xsk_session')).to be(app)
    end

    it 'is idempotent — installing twice wires the app only once' do
      described_class.protect(app, audience: 'aud', session_key: '_xsk_session')
      described_class.protect(app, audience: 'aud', session_key: '_xsk_session')

      expect(app).to have_received(:use).with(CloudflareAccessGate::Gate, audience: 'aud').once
      expect(app).to have_received(:use).with(CloudflareAccessGate::AuditLogger).once
      expect(app).to have_received(:use).with(ActionDispatch::Cookies).once
      expect(app).to have_received(:use).with(ActionDispatch::Session::CookieStore, key: '_xsk_session').once
    end
  end

  describe '.logger_for' do
    it 'wraps the configured logger' do
      logger = Logger.new(StringIO.new)
      described_class.logger = logger

      expect(described_class.logger_for('anything').target).to be(logger)
    end

    it 'falls back to a named SemanticLogger when one is loaded' do
      expect(described_class.logger_for('some-name').target).to be_a(SemanticLogger::Logger)
    end
  end
end
