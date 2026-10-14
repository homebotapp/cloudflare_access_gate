# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CloudflareAccessGate::Verifier do
  subject(:verifier) { described_class.new(audience: audience, team_domain: team_domain, clock: -> { @clock_time }) }

  let(:team_domain) { 'example' }
  let(:issuer) { "https://#{team_domain}.cloudflareaccess.com" }
  let(:certs_url) { "#{issuer}/cdn-cgi/access/certs" }
  let(:audience) { 'test-audience-tag' }

  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk) { JWT::JWK.new(rsa_key) }
  let(:jwks_response) { { 'keys' => [jwk.export] }.to_json }

  # Signs a token with the JWKS key, defaulting to every claim the verifier checks.
  def signed_token(key: rsa_key, **claims)
    payload = {
      aud: [audience],
      iss: issuer,
      email: 'user@example.com',
      exp: Time.now.to_i + 3600,
      iat: Time.now.to_i
    }.merge(claims)

    JWT.encode(payload, key, 'RS256', { kid: jwk.kid })
  end

  before do
    @clock_time = 1_000.0

    stub_request(:get, certs_url)
      .to_return(status: 200, body: jwks_response, headers: { 'Content-Type' => 'application/json' })
  end

  describe '#verify' do
    it 'returns the claims of a valid token' do
      claims = verifier.verify(signed_token(email: 'admin@example.com'))

      expect(claims).to include('email' => 'admin@example.com', 'aud' => [audience], 'iss' => issuer)
    end

    it 'returns nil for a nil token' do
      expect(verifier.verify(nil)).to be_nil
    end

    it 'returns nil for a blank token without fetching the JWKS' do
      expect(verifier.verify('   ')).to be_nil
      expect(WebMock).not_to have_requested(:get, certs_url)
    end

    it 'returns nil for garbage' do
      expect(verifier.verify('garbage-token')).to be_nil
    end

    it 'returns nil for the wrong audience' do
      expect(verifier.verify(signed_token(aud: ['wrong-audience']))).to be_nil
    end

    it 'returns nil for another team\'s issuer' do
      expect(verifier.verify(signed_token(iss: 'https://attacker.cloudflareaccess.com'))).to be_nil
    end

    it 'returns nil for a token signed with a different key' do
      expect(verifier.verify(signed_token(key: OpenSSL::PKey::RSA.generate(2048)))).to be_nil
    end

    it 'returns nil for an expired token' do
      expect(verifier.verify(signed_token(exp: Time.now.to_i - 3600, iat: Time.now.to_i - 3900))).to be_nil
    end

    it 'allows an expiry inside the clock-drift leeway' do
      token = signed_token(exp: Time.now.to_i - (described_class::DEFAULT_LEEWAY / 2))

      expect(verifier.verify(token)).to be_a(Hash)
    end

    it 'returns nil for a token missing a required claim' do
      token = JWT.encode({ aud: [audience], iss: issuer, iat: Time.now.to_i }, rsa_key, 'RS256', { kid: jwk.kid })

      expect(verifier.verify(token)).to be_nil
    end

    it 'returns nil for algorithm confusion (HS256 with the public key)' do
      payload = { aud: [audience], iss: issuer, exp: Time.now.to_i + 3600 }
      token = JWT.encode(payload, rsa_key.public_key.to_pem, 'HS256')

      expect(verifier.verify(token)).to be_nil
    end

    it 'returns nil when the JWKS endpoint is unavailable' do
      stub_request(:get, certs_url).to_return(status: 500)

      expect(verifier.verify(signed_token)).to be_nil
    end

    it 'caches the JWKS across calls' do
      verifier.verify(signed_token)
      verifier.verify(signed_token)

      expect(WebMock).to have_requested(:get, certs_url).once
    end

    context 'when the audience is not configured' do
      let(:audience) { nil }

      it 'fails closed without fetching the JWKS' do
        expect(verifier.verify(signed_token(aud: ['anything']))).to be_nil
        expect(WebMock).not_to have_requested(:get, certs_url)
      end
    end

    context 'when the team domain is not configured' do
      let(:team_domain) { '' }

      it 'fails closed without fetching the JWKS' do
        expect(verifier.verify(signed_token)).to be_nil
        expect(WebMock).not_to have_requested(:get, certs_url)
      end
    end
  end

  describe '#team_domain' do
    it 'falls back to CLOUDFLARE_ACCESS_TEAM_DOMAIN when none is passed' do
      allow(ENV).to receive(:fetch).and_call_original
      allow(ENV).to receive(:fetch).with('CLOUDFLARE_ACCESS_TEAM_DOMAIN', nil).and_return('from-env')

      expect(described_class.new(audience: audience).team_domain).to eq('from-env')
    end
  end

  describe '#issuer' do
    it 'derives the issuer from the team domain' do
      expect(verifier.issuer).to eq('https://example.cloudflareaccess.com')
    end
  end
end
