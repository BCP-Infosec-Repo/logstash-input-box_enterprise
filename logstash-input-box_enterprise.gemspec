Gem::Specification.new do |s|
  s.name          = 'logstash-input-box_enterprise'
  s.version       = '0.2.2'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'This plugin fetches enterprise events from Box.com to ship to a siem'
  s.description   = 'For SIEMs that do not have the capability to pull the log events from Box.com, this plugin can do the push and push to the SIEM'
  s.homepage      = 'https://github.com/SecurityRiskAdvisors/logstash-input-box_enterprise'
  s.authors       = ['SRA']
  s.email         = 'info@securityriskadvisors.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  #s.add_runtime_dependency "logstash-core-plugin-api", "~> 1.0" # Retaining logstash 2.4 compat
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud', '~> 0.0.22'
  #s.add_runtime_dependency 'logstash-mixin-http_client', ">= 2.2.4", "< 3.0.0" # Retaining logstash 2.4 compat
  s.add_runtime_dependency 'logstash-mixin-http_client', ">= 2.2.4", "< 7.0.0" # Logstash Production
  #s.add_runtime_dependency 'logstash-mixin-http_client', ">= 5.2.0", "< 7.0.0" # Logstash 5x+
  s.add_runtime_dependency 'manticore', ">=0.6.1"
  s.add_runtime_dependency 'rufus-scheduler', "~>3.0.9"
  s.add_runtime_dependency 'jwt', '~> 1.5', '>= 1.5.6'

  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'logstash-codec-json'
  s.add_development_dependency 'flores'
  s.add_development_dependency 'timecop'
  s.add_development_dependency 'rake', "~> 12.1.0"
  s.add_development_dependency 'kramdown', "~> 1.14.0"

end
