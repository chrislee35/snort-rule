# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'snort/rule/version'

Gem::Specification.new do |spec|
  spec.name          = "snort-rule"
  spec.version       = Snort::Rule::VERSION
  spec.authors       = ["chrislee35"]
  spec.email         = ["rubygems@chrislee.dhs.org"]
  spec.description   = %q{Parses and generates Snort rules similar to PERL's Snort::Rule}
  spec.summary       = %q{Class for parsing and generating Snort Rules}
  spec.homepage      = "http://github.com/chrislee35/snort-rule"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "minitest"
  spec.add_development_dependency "guard-minitest"
end
