lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name = 'fluent-plugin-modsecurity'
  s.version = '0.2'
  s.authors = ["bitsofinfo"]
  s.email = ["bitsofinfo.g@gmail.com"]
  s.description = 'Fluentd output plugin for parsing ModSecurity audit logs'
  s.summary = s.description
  s.homepage = 'https://github.com/bitsofinfo/fluentd-modsecurity'
  s.license = 'Apache-2.0'

  s.files = ["lib/fluent/plugin/out_modsecurity-audit-format.rb"]
  s.require_paths = ["lib"]

  s.add_development_dependency "bundler", "~> 1.14"
  s.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]

end
