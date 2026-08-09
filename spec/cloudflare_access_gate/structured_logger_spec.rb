# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CloudflareAccessGate::StructuredLogger do
  describe '.wrap' do
    it 'wraps a bare logger' do
      logger = Logger.new(StringIO.new)
      expect(described_class.wrap(logger).target).to be(logger)
    end

    it 'does not double-wrap an already wrapped logger' do
      wrapped = described_class.new(Logger.new(StringIO.new))
      expect(described_class.wrap(wrapped)).to be(wrapped)
    end
  end

  context 'with a SemanticLogger target' do
    let(:target) { SemanticLogger['structured-logger-spec'] }

    it 'passes the payload through as SemanticLogger expects' do
      allow(target).to receive(:warn)

      described_class.new(target).warn('denied', reason: 'no token', path: '/sidekiq')

      expect(target).to have_received(:warn).with('denied', { reason: 'no token', path: '/sidekiq' })
    end

    it 'applies named tags for the duration of the block' do
      tags_inside = nil

      described_class.new(target).tagged(user: 'admin@example.com') { tags_inside = SemanticLogger.named_tags }

      expect(tags_inside).to include(user: 'admin@example.com')
      expect(SemanticLogger.named_tags).to be_empty
    end
  end

  context 'with a stdlib Logger target' do
    let(:io) { StringIO.new }
    let(:target) { Logger.new(io) }

    it 'appends the payload to the message' do
      described_class.new(target).error('fetch failed', http_status: '500')

      expect(io.string).to include('fetch failed (http_status="500")')
    end

    it 'leaves a payload-free message untouched' do
      described_class.new(target).info('hello')

      expect(io.string).to end_with("hello\n")
    end

    it 'yields the block for tagged since plain loggers cannot tag' do
      expect(described_class.new(target).tagged(user: 'admin@example.com') { :result }).to eq(:result)
    end
  end

  it 'yields without tags for any logger when no tags are given' do
    target = Logger.new(StringIO.new)
    expect(described_class.new(target).tagged { :result }).to eq(:result)
  end
end
