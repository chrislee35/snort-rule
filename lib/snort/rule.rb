require "snort/rule/version"
require "snort/rule/option"
# Generates and parses snort rules
#
# Author::    Chris Lee  (mailto:rubygems@chrislee.dhs.org)
# Copyright:: Copyright (c) 2011 Chris Lee
# License::   Distributes under the same terms as Ruby
module Snort

	# This class stores and generates the features of a snort rule
	class Rule
	  attr_accessor :action, :proto, :src, :sport, :dir, :dst, :dport, :opts
    attr_reader :options

    # Initializes the Rule
    # @param [Hash] kwargs The options to initialize the Rule with
    # @option kwargs [String] :action The action
    # @option kwargs [String] :proto The protocol
    # @option kwargs [String] :src The source IP
    # @option kwargs [String] :sport The source Port
    # @option kwargs [String] :dir The direction of traffic flow
    # @option kwargs [String] :dst The destination IP
    # @option kwargs [String] :dport The destination Port
    # @option kwargs [Hash] :opts The (OLD AND BUSTED) way of passing in rule options.
    #   This only works in very simple cases, and very poorly.
    #   This is left here only for backwards compatibility. Please don't use this anymore.
    # @option kwargs[Array<Snort::RuleOption>] :options The better way of passing in options, using
    #   option objects that know how to represent themselves as a string properly
		def initialize(kwargs={})
			@action = kwargs[:action] || 'alert'
			@proto = kwargs[:proto] || 'IP'
			@src = kwargs[:src] || 'any'
			@sport = kwargs[:sport] || 'any'
			@dir = kwargs[:dir] || '->'
			@dst = kwargs[:dst] || 'any'
			@dport = kwargs[:dport] || 'any'
			@opts = kwargs[:opts] || {}
      @options = kwargs[:options] || []
		end

		# Output the current object into a snort rule
		def to_s(options_only=false)
			rule = ""
			rule = [@action, @proto, @src, @sport, @dir, @dst, @dport].join(" ") unless options_only

			if opts && opts.any?
  		  rule += " (" unless options_only
  			opts.keys.sort.each do |k|
	  			rule += k if opts[k];
		  		unless opts[k] == true
			  		rule += ":#{opts[k]}"
			  	end
				  rule += "; "
			  end
			  rule += ")" unless options_only
      end

      if options.any?
        rule += " (" unless options_only
        rule += options.join(' ')
        rule += ")" unless options_only
      end

			rule
		end

		# Parse a snort rule to generate an object
		def Rule::parse(string)
			rule = Snort::Rule.new
			rulepart, optspart = string.split(/\s*\(\s*/,2)
			rule.action, rule.proto, rule.src, rule.sport, rule.dir, rule.dst, rule.dport = rulepart.split(/\s+/)
			rule.opts = Hash[optspart.gsub(/;\s*\).*$/,'').split(/\s*;\s*/).map { |x|
				if x =~ /(.*?):(.*)/
					x.split(/:/,2)
				else
					[x,true]
				end
			}] if optspart
			rule
		end
	end
end
