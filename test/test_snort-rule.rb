require 'helper'

class TestSnortRule < Test::Unit::TestCase
	should "constructor should set all the parameters and generate the correct rule" do
		rule = Snort::Rule.new({:action => 'pass', :proto => 'udp', :src => '192.168.0.1', :sport => 'any', :dir => '<>', :dst => 'any', :dport => 53, :opts => {'sid' => 48, 'threshold' => 'type limit,track by_src,count 1,seconds 3600' }})
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end

	should "construct a default rule and update each member to generate the correct rule" do
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

	should "parse an existing rule and generate the same rule" do
		rule = Snort::Rule.parse("pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )")
		assert_equal rule.to_s, "pass udp 192.168.0.1 any <> any 53 ( sid:48; threshold:type limit,track by_src,count 1,seconds 3600; )"
	end
end
