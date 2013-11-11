# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)

Gem::Specification.new do |s|
  s.name          = "fluent-plugin-modsecurity"
  s.version       = '0.1'
  s.authors       = ["bitsofinfo"]
  s.email         = ["bitsofinfo.g@gmail.com"]
  s.description   = %q{Fluentd example output plugin for parsing modsecurity audit logs}
  s.summary       = s.description
  s.homepage      = "https://github.com/bitsofinfo/fluentd-modsecurity"
  s.license       = 'Apache 2.0'

  s.files         = ["lib/fluent/plugin/out_modsecurity-audit-format.rb"]
  
  s.add_development_dependency "fluentd"
  s.add_runtime_dependency "fluentd"
end
