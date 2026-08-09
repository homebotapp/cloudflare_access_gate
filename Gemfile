# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

# The middleware supports both Rack 2 and Rack 3, whose response-header rules
# differ. CI pins each in turn so both are actually exercised; see
# .github/workflows/ci.yml. Unset, Bundler resolves whatever is current.
rack_version = ENV.fetch('RACK_VERSION', nil)
gem 'rack', "~> #{rack_version}" if rack_version

# Rack 2 predates the Rails versions that allow Rack 3, so pin actionpack to a
# release that still accepts Rack 2 when testing that combination.
gem 'actionpack', '~> 7.0' if rack_version&.start_with?('2')
