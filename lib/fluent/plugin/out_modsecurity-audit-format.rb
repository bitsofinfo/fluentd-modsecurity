# if you want to get GeoIP info
# against the X-Forwarded-For: header
# uncomment the require below and @see https://github.com/da4nik/geoip2
#require 'GeoIP2'


#############################################
#
# Example Modsecurity output plugin for 
# parsing a modsecurity audit log entries
# @see https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats
# @see http://bitsofinfo.wordpress.com/2013/11/11/modsecurity-audit-logs-fluentd/
# @author bitsofinfo.g [ a t ] gmail.com
############################################
class ModsecurityAuditFormat < Fluent::Output
  Fluent::Plugin.register_output('modsecurity-audit-format', self)

  # Override the 'configure_parser(conf)' method.
  # You can get config parameters in this method.
  def configure(conf)
    super
    @tag = conf['tag']
  end

   # Convert the raw message and re-emit
   def emit(tag, es, chain)
    es.each do |time,record|
      modsecRecord = convertToModsecRecord(record['message'])
      Fluent::Engine.emit(@tag, time, modsecRecord)
      chain.next
    end
   end
  
  
  
  #
  # Take the raw "message"
  # and turn it into a structured
  # object with the audit record
  # fully parsed into an event
  #
  def convertToModsecRecord(message) 
     
     rawSections = Hash.new
      
     if !message.nil?
      
      modSecSectionData = message.split(/(--[a-fA-F0-9]{8}-[A-Z]--)/)
      modSecSectionData.shift  
      
      for i in 0..(modSecSectionData.length-1)
         sectionName = modSecSectionData.shift
         
         if sectionName.nil? 
           break
         end
         
         sectionData = modSecSectionData.shift
         
         if sectionName.include? '-A--'
            sectionName = 'rawSectionA' 
         elsif sectionName.include? '-B--'
            sectionName = 'rawSectionB' 
         elsif sectionName.include? '-C--'
            sectionName = 'rawSectionC'
         elsif sectionName.include? '-D--' 
            sectionName = 'rawSectionD' 
         elsif sectionName.include? '-E--'
            sectionName = 'rawSectionE'
         elsif sectionName.include? '-F--'
            sectionName = 'rawSectionF' 
         elsif sectionName.include? '-G--' 
           sectionName = 'rawSectionG' 
         elsif sectionName.include? '-H--' 
           sectionName = 'rawSectionH' 
         elsif sectionName.include? '-I--' 
           sectionName = 'rawSectionI'
         elsif sectionName.include? '-J--' 
           sectionName = 'rawSectionJ' 
         elsif sectionName.include? '-K--' 
           sectionName = 'rawSectionK' 
         else 
           sectionName = '' 
         end
         
         if !sectionName.nil? and sectionName != '' and sectionName != 'null' and sectionName != ' ' 
           sectionName = sectionName.strip 

           if !sectionData.nil?
           	  sectionData = sectionData.strip
           end
           
           rawSections[sectionName] = sectionData 
         end

      end
      
    end
    
    # convert raw sections
    return processRawSections(rawSections)
    
  end
  
  
  # Only processing these sections for now
  # others could be added if needed
  def processRawSections(rawSections) 
     
     a_hash = processSectionA(rawSections['rawSectionA'])
     b_hash = processSectionB(rawSections['rawSectionB'])
     c_hash = processSectionC(rawSections['rawSectionC'])
     f_hash = processSectionF(rawSections['rawSectionF'])
     h_hash = processSectionH(rawSections['rawSectionH'])
     k_hash = processSectionK(rawSections['rawSectionK'])
     
     return a_hash.merge(b_hash).merge(c_hash).merge(f_hash).merge(h_hash).merge(k_hash)
     
  end   
  
  def processSectionA(section) 
     if section.nil?
        return Hash.new
     end
     matchData = section.match(/\[(?<modsec_timestamp>.+)\]\s(?<uniqueId>.+)\s(?<sourceIp>.+)\s(?<sourcePort>.+)\s(?<destIp>.+)\s(?<destPort>.+)/)
     hash = Hash[matchData.names.zip(matchData.captures)]
     return hash
  end
  
  def processSectionB(section) 
    
     hash = Hash.new
    
     # line #1
     if section =~ /.*?\s\S+\s.+\n{1}/
    
       matchData = section.match(/(?<httpMethod>.*?)\s(?<requestedUri>\S+)\s(?<incomingProtocol>.+)\n{1}/)
       hash = hash.merge(Hash[matchData.names.zip(matchData.captures)])
       
     else 
       
       matchData = section.match(/(?<httpMethod>^(.*)$)/)
       hash = hash.merge(Hash[matchData.names.zip(matchData.captures)])

     end
     
     # request headers
     if section =~ /.+\n(?m).+/
       
       matchData = section.match(/.+\n(?m)(?<raw_requestHeaders>.+)/)
       hash = hash.merge(Hash[matchData.names.zip(matchData.captures)])
       
           
       if hash['raw_requestHeaders'] =~ /X-Forwarded-For:/
          matchData = hash['raw_requestHeaders'].match(/X-Forwarded-For: (?<XForwardedFor>.+)$/)
          hash = hash.merge(Hash[matchData.names.zip(matchData.captures)]) 
          
               
          # if you want to get GeoIP info
          # against the X-Forwarded-For: header
          # uncomment this and @see https://github.com/da4nik/geoip2
          #geoip = GeoIP2::locate('/path/to/GeoLite2-City.mmdb', hash['XForwardedFor'], 'en')
          #hash['XForwardedFor-GEOIP'] = geoip
          
       end 
       
       # example of getting a custom cookie and promoting to 1st class field
       if hash['raw_requestHeaders'] =~ /Cookie:/ and hash['raw_requestHeaders'] =~ /myCookie=.+\b/
          matchData = hash['raw_requestHeaders'].match(/(?<myCookie>myCookie[^; \s]+)/)
          hash = hash.merge(Hash[matchData.names.zip(matchData.captures)]) 
       end 
       
       # split all request headers into a sub-map
       hash['requestHeaders'] = Hash.new
       hash['raw_requestHeaders'].split(/\n/).each do |header|
            parts = header.split(/:/)
            hash['requestHeaders'][parts[0].strip] = parts[1].strip
       end
       
       hash.delete('raw_requestHeaders')
       
     end
     
     
     return hash
     
  end
  
  def processSectionC(section) 
    
     if section =~ /.+/
    
       matchData = section.match(/(?<requestBody>.+)/)
       hash = Hash[ matchData.names.zip(matchData.captures)]
       return hash
       
     else 
       
       return Hash.new
       
     end
  end
  
  
  def processSectionF(section) 
    
     if section =~ /.+/
       
       # line 1
       matchData = section.match(/(?<serverProtocol>.+?)\s(?<responseStatus>.+)\n{1}/)
       hash = Hash[ matchData.names.zip(matchData.captures)]
       
       # response headers
       matchData = section.match(/.+\n(?m)(?<raw_responseHeaders>.+)/)
       hash = hash.merge(Hash[ matchData.names.zip(matchData.captures)])
       
       hash['responseHeaders'] = Hash.new
       hash['raw_responseHeaders'].split(/\n/).each do |header|
            parts = header.split(/:/)
            hash['responseHeaders'][parts[0].strip] = parts[1].strip
       end
       
       hash.delete('raw_responseHeaders')
     
     else 
       
       hash = Hash.new
       
     end
     
     return hash
  end
  
  
  
  
   def extractVal(pattern, fromString, storeResultIn, underKeyName)
     result = pattern.match(fromString)
     if !result.nil?
       storeResultIn[underKeyName] = result[1]
     end
   end
  
  
  
  
   def processSectionH(section) 
    
     hash = Hash.new
    
     if section =~ /.+/
       
       
         # build audit log trailer messages
         auditLogTrailerMessages = Array.new()
         trailer_array = section.split(/\n/)
         
         trailer_array.each do |entry|
           if entry.match(/^Message: /)
              msg = Hash.new()
              extractVal(/Message: (.+)\s($|(\s*\[file))/, entry, msg, 'info')
              extractVal(/\[file \"(.*?)\"\]/, entry, msg, 'file')
              extractVal(/\[line \"(.*?)\"\]/, entry, msg, 'line')
              extractVal(/\[id \"(.*?)\"\]/, entry, msg, 'id')
              extractVal(/\[msg \"(.*?)\"\]/, entry, msg, 'msg')
              extractVal(/\[severity \"(.*?)\"\]/, entry, msg, 'severity')
              extractVal(/\[data \"(.*?)\"\]/, entry, msg, 'data')
              extractVal(/\[tag \"(.*?)\"\]/, entry, msg, 'tag')
              auditLogTrailerMessages.push(msg); 
           end
        end
        
        
        #key/value pair of audit log trailer
       hash['auditLogTrailer'] = Hash.new
       section.split(/\n/).each do |line|
            parts = line.split(/:\s/)
            hash['auditLogTrailer'][parts[0].strip] = parts[1].strip
       end
       
       hash['auditLogTrailer'].delete('Message')
       hash['auditLogTrailer']['messages'] = auditLogTrailerMessages
        
     end
     
     
     if section =~ /Stopwatch/
        matchData = section.match(/Stopwatch: (?<event_date_microseconds>\b\w+\b)/)
        hash = hash.merge(Hash[matchData.names.zip(matchData.captures)])
        
        # convert to float
        hash['event_date_microseconds'] = hash['event_date_microseconds'].to_f
 
        hash['event_date_milliseconds'] = (hash['event_date_microseconds'] / 1000.0)
        hash['event_date_seconds'] = (hash['event_date_milliseconds'] / 1000.0)
        hash['event_timestamp'] = (Time.at(hash['event_date_seconds']).gmtime).iso8601(3)
        
     end
     
     return hash
     
   end
   
   
   
   
   
   
   def processSectionK(section) 
    
     if section =~ /.+/
       
       # convert to array
       matchedRules_array = section.split(/\n/)
       
       secRuleIds = Array.new()
       
       matchedRules_array.each do |entry|
         if entry.match(/^SecRule /) and entry.match(/,id:/)
           secRuleIds.push(/,id:(?<ruleId>\d+)/.match(entry)[:ruleId])
         end
       end
       
       hash = Hash.new
       hash['secRuleIds'] = secRuleIds
       hash['matchedRules'] = matchedRules_array
       return hash

     else 
       
       hash = Hash.new
       
     end
     
  end
  
end
