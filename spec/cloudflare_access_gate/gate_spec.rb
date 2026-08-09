# frozen_string_literal: true

require 'spec_helper'

RSpec.describe CloudflareAccessGate::Gate do
  let(:inner_app) { ->(_env) { [200, {}, ['OK']] } }
  let(:middleware) do
    described_class.new(inner_app, audience: audience, team_domain: team_domain, clock: -> { @clock_time })
  end
  let(:env) { Rack::MockRequest.env_for('/sidekiq') }

  let(:team_domain) { 'example' }
  let(:issuer) { "https://#{team_domain}.cloudflareaccess.com" }
  let(:certs_url) { "#{issuer}/cdn-cgi/access/certs" }
  let(:audience) { 'test-audience-tag' }

  let(:cache_ttl) { CloudflareAccessGate::JwksCache::CACHE_TTL }
  let(:error_backoff) { CloudflareAccessGate::JwksCache::ERROR_BACKOFF }
  let(:stale_grace) { CloudflareAccessGate::JwksCache::DEFAULT_STALE_GRACE }

  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk) { JWT::JWK.new(rsa_key) }
  let(:jwks_response) { { 'keys' => [jwk.export] }.to_json }

  let(:valid_token) { signed_token }

  # Signs a token with the JWKS key, defaulting to every claim the gate verifies.
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

    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_GATE', 'true').and_return('true')
    allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true').and_return('false')
    stub_request(:get, certs_url)
      .to_return(status: 200, body: jwks_response, headers: { 'Content-Type' => 'application/json' })
  end

  context 'when gate is disabled' do
    before do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_GATE', 'true').and_return('false')
    end

    it 'passes through to the app without checking tokens' do
      status, = middleware.call(env)
      expect(status).to eq(200)
    end
  end

  context 'fail-closed flag semantics' do
    it 'stays enabled for a non-"false" value like "0" (403 without a token)' do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_GATE', 'true').and_return('0')
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'defaults to enabled when ENABLE_CLOUDFLARE_GATE is unset (403 without a token)' do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_GATE', 'true').and_return('true')
      expect(described_class.enabled?).to be(true)
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'keeps JWT validation on for a non-"false" value like "0" (403 for an unverifiable token)' do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true').and_return('0')
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'garbage-token'
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'defaults JWT validation to on when unset' do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true').and_return('true')
      expect(described_class.jwt_validation_enabled?).to be(true)
    end
  end

  context 'when gate is enabled without JWT validation' do
    it 'returns 403 when no token header is present' do
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns a plain-text Forbidden response body for a denied request' do
      status, headers, body = middleware.call(env)
      expect(status).to eq(403)
      expect(headers['content-type']).to eq('text/plain')
      expect(body).to eq(['Forbidden'])
    end

    it 'returns 403 when token header is an empty string' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = ''
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns 403 when token header is whitespace only' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = '   '
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'passes through when token header is present without validating it' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'any-token-value'
      status, = middleware.call(env)
      expect(status).to eq(200)
    end
  end

  context 'when gate is enabled with JWT validation' do
    before do
      allow(ENV).to receive(:fetch).with('ENABLE_CLOUDFLARE_JWT_VALIDATION', 'true').and_return('true')
    end

    it 'returns 403 when no JWT is present' do
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns 403 when JWT is invalid' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = 'garbage-token'
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns 403 when JWT has wrong audience' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = signed_token(aud: ['wrong-audience'])
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns 403 when JWT is signed with a different key' do
      # Uses a real kid so JWKS lookup succeeds and the signature check itself is
      # what rejects the token (not a missing-key resolution failure).
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = signed_token(key: OpenSSL::PKey::RSA.generate(2048))
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'returns 403 when JWT is expired' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = signed_token(exp: Time.now.to_i - 3600, iat: Time.now.to_i - 3900)
      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'allows an expiry inside the clock-drift leeway' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] =
        signed_token(exp: Time.now.to_i - (described_class::DEFAULT_LEEWAY / 2))
      status, = middleware.call(env)
      expect(status).to eq(200)
    end

    it 'returns 403 when JWT uses algorithm confusion (HS256 with public key)' do
      confused_payload = {
        aud: [audience], iss: issuer, email: 'attacker@evil.example',
        exp: Time.now.to_i + 3600, iat: Time.now.to_i
      }
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = JWT.encode(confused_payload, rsa_key.public_key.to_pem, 'HS256')

      status, = middleware.call(env)
      expect(status).to eq(403)
    end

    it 'passes through when JWT is valid' do
      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
      status, = middleware.call(env)
      expect(status).to eq(200)
    end

    describe 'required claims' do
      # `verify_expiration`/`verify_iss`/`verify_aud` only check a claim when it
      # is present, so each of these would otherwise be accepted outright.
      it 'returns 403 when the token carries no exp claim' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] =
          JWT.encode({ aud: [audience], iss: issuer, iat: Time.now.to_i }, rsa_key, 'RS256', { kid: jwk.kid })

        status, = middleware.call(env)

        expect(status).to eq(403)
      end

      it 'returns 403 when the token carries no aud claim' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] =
          JWT.encode({ iss: issuer, exp: Time.now.to_i + 3600 }, rsa_key, 'RS256', { kid: jwk.kid })

        status, = middleware.call(env)

        expect(status).to eq(403)
      end

      it 'returns 403 when the token carries no iss claim' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] =
          JWT.encode({ aud: [audience], exp: Time.now.to_i + 3600 }, rsa_key, 'RS256', { kid: jwk.kid })

        status, = middleware.call(env)

        expect(status).to eq(403)
      end
    end

    describe 'issuer verification' do
      it 'returns 403 when the issuer claim belongs to another Access team' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = signed_token(iss: 'https://attacker.cloudflareaccess.com')
        status, = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'returns 403 when the issuer claim is absent' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = signed_token(iss: nil)
        status, = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when the audience is not configured' do
      let(:audience) { nil }

      it 'fails closed and returns 403 even for an otherwise valid token' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        status, = middleware.call(env)
        expect(status).to eq(403)
      end
    end

    context 'when the team domain is not configured' do
      let(:team_domain) { '' }

      it 'fails closed without attempting a JWKS fetch' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token

        status, = middleware.call(env)

        expect(status).to eq(403)
        expect(WebMock).not_to have_requested(:get, certs_url)
      end
    end

    it 'falls back to CLOUDFLARE_ACCESS_TEAM_DOMAIN when no team domain is passed' do
      allow(ENV).to receive(:fetch).with('CLOUDFLARE_ACCESS_TEAM_DOMAIN', nil).and_return(team_domain)
      gate = described_class.new(inner_app, audience: audience)

      env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
      status, = gate.call(env)

      expect(status).to eq(200)
    end

    describe 'JWKS caching' do
      it 'caches JWKS across requests' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        middleware.call(env)
        middleware.call(env)

        expect(WebMock).to have_requested(:get, certs_url).once
      end

      it 'refreshes JWKS cache after TTL expires' do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        middleware.call(env)

        @clock_time += cache_ttl + 1
        middleware.call(env)

        expect(WebMock).to have_requested(:get, certs_url).twice
      end
    end

    describe 'JWKS fetch failures' do
      it 'returns 403 when the JWKS endpoint returns a non-JSON body' do
        stub_request(:get, certs_url)
          .to_return(status: 200, body: '<html>Error</html>', headers: { 'Content-Type' => 'text/html' })

        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        status, = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'returns 403 when the JWKS endpoint is unavailable' do
        stub_request(:get, certs_url).to_return(status: 500)

        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        status, = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'returns 403 when the JWKS response contains no keys' do
        stub_request(:get, certs_url)
          .to_return(status: 200, body: { 'keys' => [] }.to_json,
                     headers: { 'Content-Type' => 'application/json' })

        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        status, = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'returns 403 when the JWKS keys carry no key type' do
        stub_request(:get, certs_url)
          .to_return(status: 200, body: { 'keys' => [{}] }.to_json,
                     headers: { 'Content-Type' => 'application/json' })

        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        status, = middleware.call(env)
        expect(status).to eq(403)
      end

      it 'backs off instead of re-fetching on every request during an outage' do
        stub_request(:get, certs_url).to_return(status: 500)
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token

        3.times { middleware.call(env) }

        expect(WebMock).to have_requested(:get, certs_url).once
      end

      it 'retries once the error backoff has elapsed' do
        stub_request(:get, certs_url).to_return(status: 500)
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token

        middleware.call(env)
        @clock_time += error_backoff + 1
        middleware.call(env)

        expect(WebMock).to have_requested(:get, certs_url).twice
      end
    end

    describe 'stale JWKS handling' do
      before do
        env['HTTP_CF_ACCESS_JWT_ASSERTION'] = valid_token
        middleware.call(env) # prime the cache with a good fetch
        stub_request(:get, certs_url).to_return(status: 500)
      end

      it 'keeps serving the good key set when a refresh returns unusable keys' do
        stub_request(:get, certs_url)
          .to_return(status: 200, body: { 'keys' => [{}] }.to_json,
                     headers: { 'Content-Type' => 'application/json' })
        @clock_time += cache_ttl + 1

        status, = middleware.call(env)

        expect(status).to eq(200)
      end

      it 'serves a stale JWKS inside the grace window when a refresh fails' do
        @clock_time += cache_ttl + 1

        status, = middleware.call(env)

        expect(status).to eq(200)
      end

      it 'denies once the stale JWKS is older than the grace window' do
        @clock_time += cache_ttl + stale_grace + 2

        status, = middleware.call(env)

        expect(status).to eq(403)
      end

      context 'with the grace window disabled' do
        let(:middleware) do
          described_class.new(inner_app, audience: audience, team_domain: team_domain,
                                         jwks_stale_grace: 0, clock: -> { @clock_time })
        end

        it 'denies as soon as the cache expires and a refresh fails' do
          @clock_time += cache_ttl + 1

          status, = middleware.call(env)

          expect(status).to eq(403)
        end
      end
    end
  end
end
