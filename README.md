# fluentd-modsecurity

[Fluentd](http://fluentd.org/) output (filter) plugin for parsing a [ModSecurity](https://www.modsecurity.org/) audit log

This is intended to serve as an example starting point for how to ingest
parse entries from a ModSecurity audit log file using fluentd into a more first-class
structured object that can then be forwarded on to another output.

## Getting Started

More info and example output:
* http://bitsofinfo.wordpress.com/2013/11/11/modsecurity-audit-logs-fluentd/

ModSecurity Audit Log format:
* https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats
* https://www.nginx.com/blog/modsecurity-logging-and-debugging/

### Prerequisites

Build the gem
```
gem build fluent-plugin-modsecurity.gemspec
``` 

Install the gem to fluentd
```
fluent-gem install ./fluent-plugin-modsecurity-0.2.gem
``` 

## Deployment

Example fluent.conf setup.

```
# (1) Consume the input
<source>
  @type tail
  tag raw-modsec
  path /path/to/modsec_audit.log
  <parse>
    @type multiline
    format_firstline /^-{2,3}][a-zA-Z0-9]{8}-{2,3}A--$/
    format1 /(?<message>.*)/
  </parse>
</source>

# (2) Massage it via this plugin to a more structured object
<match raw-modsec>
  @type modsecurity-audit-format
  tag modsec-formatted
</match>

# (3) Output to stdout
<match modsec-formatted>
  @type stdout
</match>
```

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details