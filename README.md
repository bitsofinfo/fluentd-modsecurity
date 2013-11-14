fluentd-modsecurity
===================

Output (filter) plugin for parsing a ModSecurity audit log

This is intended to serve as an example starting point for how to ingest
parse entries from a ModSecurity audit log file using Fluentd into a more first-class
structured object that can then be forwarded on to another output.

This depends on the tail_multiline Fluentd input plugin located 
at https://github.com/tomohisaota/fluent-plugin-tail-multiline

see: http://fluentd.org/

see: https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats

license: http://www.apache.org/licenses/LICENSE-2.0 

More info and example output: http://bitsofinfo.wordpress.com/2013/11/11/modsecurity-audit-logs-fluentd/

To install this output filter plugin:

(1) Install geoip support instructions here: https://github.com/mtodd/geoip


(2) Run the following commands from the root of this project

```
gem build fluent-plugin-modsecurity.gemspec
fluent-gem install ./fluent-plugin-modsecurity-0.1.gem
``` 

Your fluent.conf should look like this:

```
# (1) Consume the input
<source>
  type tail_multiline
  tag raw-modsec
  format /(?<message>.*)/
  format_firstline /^--[a-fA-F0-9]{8}-A--$/
  path /path/to/your/modsecurity_audit.log
</source>

# (2) Massage it via this plugin to a more structured object
<match raw-modsec>
  type modsecurity-audit-format
  tag modsec-formatted
</match>

# (3) Output to stdout
<match modsec-formatted>
  type stdout
</match>
```
