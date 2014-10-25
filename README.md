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
	rule = Snort::Rule.new({:enabled => true, :action => 'pass', :proto => 'udp', :src => '192.168.0.1', :sport => 'any', :dir => '<>', :dst => 'any', :dport => 53, :opts => {'sid' => 48, 'threshold' => 'type limit,track by_src,count 1,seconds 3600' }})

	rule.to_s => "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"

	rule = Snort::Rule.new
	rule.enabled = false
	rule.action = 'pass'
	rule.proto = 'udp'
	rule.src = '192.168.0.1'
	rule.dir = '<>'
	rule.dport = 53
	rule.options << Snort::RuleOption.new('sid', 48)
	rule.options << Snort::RuleOption.new('threshold', 'type limit,track by_src,count 1,seconds 3600')
	rule.options << Snort::RuleOption.new('ref', 'ref1')
	rule.options << Snort::RuleOption.new('ref', 'ref2')
	rule.options.each do |opt|
		puts opt
	end
	rule.options_hash["sid"] == 48
	rule.options_hash["ref"] == "ref2"

	# if the rule is disabled, then it will begin with a #
	rule.to_s => "#pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"

	rule = Snort::Rule.parse("pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )")
	rule.to_s => "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

Thanks so much for those who have already contributed.

<a href='mailto:github@chrislee[dot]dhs[dot]org[stop here]xxx'><img src='http://chrisleephd.us/images/github-email.png?snort-rule'></a>