unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

class TestSnortRule < Minitest::Test
	def test_constructor_should_set_all_the_parameters_and_generate_the_correct_rule
		rule = Snort::Rule.new({:action => 'pass', :proto => 'udp', :src => '192.168.0.1', :sport => 'any', :dir => '<>', :dst => 'any', :dport => 53, :opts => {'sid' => 48, 'threshold' => 'type limit,track by_src,count 1,seconds 3600' }})
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end

	def test_construct_a_default_rule_and_update_each_member_to_generate_the_correct_rule
		rule = Snort::Rule.new
		rule.action = 'pass'
		rule.proto = 'udp'
		rule.src = '192.168.0.1'
		rule.dir = '<>'
		rule.dport = 53
		rule.opts['sid'] = 48
		rule.opts['threshold'] = 'type limit,track by_src,count 1,seconds 3600'
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
  end

  def test_construct_a_default_rule_with_many_options_having_the_same_keyword
    rule = Snort::Rule.new
    rule.action = 'alert'
    rule.proto = 'tcp'
    rule.src = '$HOME_NET'
    rule.dir = '->'
    rule.dst = '$EXTERNAL_NET'
    rule.dport = '$HTTP_PORTS'
    rule.options << Snort::RuleOption.new('msg', '"HTTP Host www.baddomain.com"')
    rule.options << Snort::RuleOption.new('content', '"Host|3a|"')
    rule.options << Snort::RuleOption.new('nocase')
    rule.options << Snort::RuleOption.new('http_header')
    rule.options << Snort::RuleOption.new('content', '"www.baddomain.com"')
    rule.options << Snort::RuleOption.new('nocase')
    rule.options << Snort::RuleOption.new('http_header')
    rule.options << Snort::RuleOption.new('pcre', '"/^Host\\x3a(.*\\.|\\s*)www\\.baddomain\\.com\\s*$/mi"')
    rule.options << Snort::RuleOption.new('flow', 'to_server,established')
    rule.options << Snort::RuleOption.new('threshold', 'type limit, track by_src, count 1, seconds 300')
    rule.options << Snort::RuleOption.new('classtype', 'bad-unknown')
    rule.options << Snort::RuleOption.new('sid', '100000000')
    assert_equal 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"HTTP Host www.baddomain.com"; content:"Host|3a|"; nocase; http_header; content:"www.baddomain.com"; nocase; http_header; pcre:"/^Host\x3a(.*\.|\s*)www\.baddomain\.com\s*$/mi"; flow:to_server,established; threshold:type limit, track by_src, count 1, seconds 300; classtype:bad-unknown; sid:100000000;)', rule.to_s
  end

	def test_parse_an_existing_rule_and_generate_the_same_rule
		rule = Snort::Rule.parse("pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )")
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 (sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end
end
