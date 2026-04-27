$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "minitest/reporters"
require "webmock/minitest"
require "stackwatch"
require "stackwatch/config"

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

WebMock.disable_net_connect!

def fixture(name)
  File.read(File.expand_path("fixtures/#{name}", __dir__))
end

def fixture_path(name)
  File.expand_path("fixtures/#{name}", __dir__)
end
