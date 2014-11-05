require "snort/rule/version"
require "snort/rule/option"
# Generates and parses snort rules
#
# Authors::   Chris Lee  (mailto:rubygems@chrislee.dhs.org),
#             Will Green (will[ at ]hotgazpacho[ dot ]org),
#             Justin Knox (jknox[ at ]indexzero[ dot ]org)
#             Ryan Barnett (rbarnett[ at ]modsecurity[ dot ]org)
# Copyright:: Copyright (c) 2011 Chris Lee
# License::   Distributes under the same terms as Ruby
module Snort

  # This class stores and generates the features of a snort rule
  class Rule
    attr_accessor :enabled, :action, :proto, :src, :sport, :dir, :dst, :dport, :options_hash
    attr_reader :options
    ARGLESS = [
      "http_method", 
			"ftpbounce",
			"file_data",
			"nocase",
			"rawbytes",
			"dce_stub_data",
			"fast_pattern",
			"http_client_body", 
			"http_header",
			"http_raw_cookie",
			"http_raw_header",
			"http_method",
			"http_uri",
			"http_stat_code",
			"http_stat_msg",
			"http_cookie"
    ]
    HKEYWORDS = [
      "msg",
			"content",
			"gid",
			"sid", 
			"ttl", 
			"uricontent",
			"pcre",
			"flow",
			"nocase",
			"rev",
			"reference",
			"classtype",
			"flowbits",
			"threshold",
			"offset",
			"distance",
			"within",
			"offset",
			"depth",
			"dsize",
			"byte_test",
			"byte_jump",
			"rawbytes",
			"isdataat",
			"ipopts",
			"tag",
			"itype",
			"icode",
			"flags",
			"urilen",
			"fragbits",
			"fragoffset",
			"seq",
			"ack",
			"window",
			"id",
			"ip_proto",
			"metadata",
			"priority",
			"fwsam",
			"asn1",
			"http_client_body",
			"http_cookie",
			"dce_stub_data",
			"dce_iface",
			"dce_opnum",
			"http_header",
			"icmp_id",
			"icmp_seq",
			"fast_pattern",
			"http_method",
			"ftpbounce",
			"http_encode",
			"http_stat_code",
			"http_stat_msg",
      "http_uri",
      "ssl_version",
      "ssl_state",
			"detection_filter",
			"file_data"
    ]
    
    # Initializes the Rule
    # @param [Hash] kwargs The options to initialize the Rule with
    # @option kwargs [String] :enabled true or false
    # @option kwargs [String] :action The action
    # @option kwargs [String] :proto The protocol
    # @option kwargs [String] :src The source IP
    # @option kwargs [String] :sport The source Port
    # @option kwargs [String] :dir The direction of traffic flow
    # @option kwargs [String] :dst The destination IP
    # @option kwargs [String] :dport The destination Port
    # @option kwargs[Array<Snort::RuleOption>] :options The better way of passing in options, using
    #   option objects that know how to represent themselves as a string properly
    def initialize(kwargs={})
      @enabled = true
      if kwargs.has_key?(:enabled) and (not kwargs[:enabled] or ['false', 'no', 'off'].index(kwargs[:enabled].to_s.downcase))
        @enabled = false
      end
      @action = kwargs[:action] || 'alert'
      @proto = kwargs[:proto] || 'IP'
      @src = kwargs[:src] || 'any'
      @sport = kwargs[:sport] || 'any'
      @dir = kwargs[:dir] || '->'
      @dst = kwargs[:dst] || 'any'
      @dport = kwargs[:dport] || 'any'
      @options = []
      @options_hash = {}
      if kwargs[:options]
        kwargs[:options].each do |opt|
          add_option(opt)
        end
      end
    end

    # Output the current object into a snort rule
    def to_s(options_only=false)
      rule = ""
      if not @enabled
        rule = "#"
      end
      rule += [@action, @proto, @src, @sport, @dir, @dst, @dport].join(" ") unless options_only
      if @options.any?
        rule += " (" unless options_only
        rule += @options.join(' ')
        rule += ")" unless options_only
      end
      rule
    end
    
    def add_option(option)
      if option.class == Array
        option = Snort::RuleOption.new(option[0], option[1,100])
      end
      @options << option
      unless @options_hash[option.keyword]
        @options_hash[option.keyword] = []
      end
      @options_hash[option.keyword] << option
    end
    
    def del_option(option)
      @options.delete(option)
      if @options_hash[option.keyword]
        @options_hash[option.keyword].delete(option)
      end
    end
    
    def clear_options()
      @options = []
      @options_hash = {}
    end

    # Parse a snort rule to generate an object
    def Rule::parse(string)
      rule = Snort::Rule.new
      # If the string begins with /^#+\s*/, then the rule is disabled.
      # If disabled, let's scrub the disabling substring from the string.
      if string.index(/^#+\s+/)
        rule.enabled = false
        string.gsub!(/^#+\s*/,'')
      end
      rulepart, optspart = string.split(/\s*\(\s*/,2)
      rule.action, rule.proto, rule.src, rule.sport, rule.dir, rule.dst, rule.dport = rulepart.split(/\s+/)
      if not ['<>', '<-', '->'].index(rule.dir)
        # most likely, I have a parse error, maybe it's just a random comment
        raise ArgumentError.new("Unable to parse rule, #{rulepart}")
      end
      optspart.gsub(/;\s*\).*$/,'').split(/\s*;\s*/).each do |x|
        if x =~ /(.*?):(.*)/
          k, v = x.split(/:/, 2)
          opt = Snort::RuleOption.new(k, v)
          rule.options << opt
          unless rule.options_hash[k]
            rule.options_hash[k] = []
          end
          rule.options_hash[k] << opt
        else
          rule.options.last.arguments << x
        end
      end if optspart
      rule
    end
  end
end
