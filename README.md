# Snort::Rule

Constructs and parses Snort rules similar to PERL's Snort::Rule.

## Installation

Add this line to your application's Gemfile:

    gem 'snort-rule'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install snort-rule

## Usage

	require 'snort/rule'
	rule = Snort::Rule.new({:enabled => true, :action => 'pass', :proto => 'udp', :src => '192.168.0.1', :sport => 'any', :dir => '<>', :dst => 'any', :dport => 53, :options => {'sid' => 48, 'threshold' => 'type limit,track by_src,count 1,seconds 3600' }})

	rule.to_s # => "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"

	rule = Snort::Rule.new
	rule.enabled = false
	rule.action = 'pass'
	rule.proto = 'udp'
	rule.src = '192.168.0.1'
	rule.dir = '<>'
	rule.dport = 53
	rule.add_option(Snort::RuleOption.new('sid', 48))
	rule.add_option(Snort::RuleOption.new('threshold', 'type limit,track by_src,count 1,seconds 3600'))
	rule.add_option(Snort::RuleOption.new('ref', 'ref1'))
	rule.add_option(Snort::RuleOption.new('ref', ['ref2', 'nocase']))
	rule.options.each do |opt|
		puts opt
	end
	rule.options_hash["sid"][0].arguments[0] # => 48
	rule.options_hash["ref"][1].arguments[0] # => "ref2"
	rule.options_hash["ref"][1].arguments[1] # => "nocase"

	# if the rule is disabled, then it will begin with a #
	rule.to_s # => #pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; sid:48; threshold:type limit,track by_src,count 1,seconds 3600; ref:ref1; ref:ref2; nocase;)"

	rule = Snort::Rule.parse("pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600;  ref:ref1; ref:ref2;)")
	rule.to_s # => "pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; ref:ref1; ref:ref2;)"

## Snort::RuleSet Usage

	require 'snort/ruleset'
	ruleset = Snort::RuleSet::from_file("community.rules")
	ruleset.length # => 3127
    rules.length
    rules.count{|r| ! r.enabled} # => 2522
    rules.count{|r| r.enabled} # => 605
    rules.disable_all
    rules.count{|r| r.enabled} # => 0
    rules.count{|r| ! r.enabled} # => 3127
    rules.enable_all
    rules.count{|r| r.enabled} # => 3127
    rules.count{|r| ! r.enabled} # => 0
    rules.disable do |r|
      r.get_option_first("msg").match(/^"MALWARE\-CNC/)
    end
    rules.count{|r| ! r.enabled} # => 392
    rules.count{|r| r.enabled} # => 2735
    rules.delete do |r|
      options = r.get_options("content")
      if options
        options.find { |o|
          o.arguments.find { |a|
            a.match(/"POST"/)
          }
        }
      else
        nil
      end
    end
    rules.count{|r| ! r.enabled} # => 343
    rules.count{|r| r.enabled} # 2726
    rules.delete_all
	rules.length # => 0
    rules.count{|r| r.enabled} # => 0
    rules.count{|r| ! r.enabled} # =>
	

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

Thanks so much for those who have already contributed.

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?snort-rule'></a>