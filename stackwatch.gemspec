require_relative "lib/stackwatch"

Gem::Specification.new do |spec|
  spec.name          = "stackwatch"
  spec.version       = StackWatch::VERSION
  spec.authors       = ["StackWatch Contributors"]
  spec.summary       = "Self-hosted CVE monitoring for your stack"
  spec.description   = "Watches a list of packages and tools, pings your Slack channel the moment a new CVE drops for any of them."
  spec.homepage      = "https://github.com/yourorg/stackwatch"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.files         = Dir["lib/**/*", "exe/*", "README.md", "LICENSE"]
  spec.bindir        = "exe"
  spec.executables   = ["stackwatch"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "thor",  "~> 1.3"
  spec.add_runtime_dependency "psych", "~> 5.1"

  spec.add_development_dependency "minitest",            "~> 5.20"
  spec.add_development_dependency "minitest-reporters",  "~> 1.6"
  spec.add_development_dependency "webmock",             "~> 3.23"
  spec.add_development_dependency "rubocop",             "~> 1.60"
end
