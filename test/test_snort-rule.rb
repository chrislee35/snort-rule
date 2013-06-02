unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

class TestSnortRule < Test::Unit::TestCase
	def test_constructor_should_set_all_the_parameters_and_generate_the_correct_rule
		rule = Snort::Rule.new({:action => 'pass', :proto => 'udp', :src => '192.168.0.1', :sport => 'any', :dir => '<>', :dst => 'any', :dport => 53, :opts => {'sid' => 48, 'threshold' => 'type limit,track by_src,count 1,seconds 3600' }})
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
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
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end

	def test_parse_an_existing_rule_and_generate_the_same_rule
		rule = Snort::Rule.parse("pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )")
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end
end
