# frozen_string_literal: true

require 'cloudflare_access_gate'

require 'rack'
require 'rack/mock'
require 'jwt'
require 'timecop'
require 'webmock/rspec'

# SemanticLogger is loaded so the SemanticLogger branch of StructuredLogger is
# covered, but the gem must not require it — see no_rails_spec.rb, which boots
# the middleware in a subprocess with neither Rails nor SemanticLogger present.
require 'semantic_logger'

# ActionDispatch is needed only by `.protect`, which is the sole Rails-dependent
# part of the gem. Everything else runs on plain Rack.
require 'action_dispatch'
require 'action_dispatch/middleware/cookies'
require 'action_dispatch/middleware/session/cookie_store'

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.mock_with(:rspec) { |c| c.verify_partial_doubles = true }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed

  # Reset the globally configurable logger between examples.
  config.after { CloudflareAccessGate.logger = nil }
end
