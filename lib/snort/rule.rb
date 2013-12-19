require "snort/rule/version"
# Generates and parses snort rules
#
# Author::    Chris Lee  (mailto:rubygems@chrislee.dhs.org)
# Copyright:: Copyright (c) 2011 Chris Lee
# License::   Distributes under the same terms as Ruby
module Snort
	# This class stores and generates the features of a snort rule
	class Rule
		attr_accessor :action, :proto, :src, :sport, :dir, :dst, :dport, :opts
		
		def initialize(kwargs={})
			@action = kwargs[:action] || 'alert'
			@proto = kwargs[:proto] || 'IP'
			@src = kwargs[:src] || 'any'
			@sport = kwargs[:sport] || 'any'
			@dir = kwargs[:dir] || '->'
			@dst = kwargs[:dst] || 'any'
			@dport = kwargs[:dport] || 'any'
			@opts = kwargs[:opts] || {}
		end
		
		# Output the current object into a snort rule
		def to_s(options_only=false)
			rule = ""
			rule = [@action, @proto, @src, @sport, @dir, @dst, @dport].join(" ") unless options_only
			
			if opts
  		  rule += "(" unless options_only
  			opts.keys.sort.each do |k|
	  			rule += k if opts[k];
		  		unless opts[k] == true
			  		rule += ":#{opts[k]}"
			  	end
				  rule += "; "
			  end
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
