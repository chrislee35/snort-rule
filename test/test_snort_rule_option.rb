unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

class TestSnortRuleOption < Minitest::Test
  def test_to_s_on_option_with_keyword_and_argument
    option = Snort::RuleOption.new('msg', '"OHAI"')
    assert_equal 'msg:"OHAI";', option.to_s
  end

  def test_to_s_on_option_with_keyword_and_no_arguments
    option = Snort::RuleOption.new('nocase')
    assert_equal 'nocase;', option.to_s
  end

  def test_two_options_with_same_keyword_and_arguments_are_double_equals
    option1 = Snort::RuleOption.new('msg', '"OHAI"')
    option2 = Snort::RuleOption.new('msg', '"OHAI"')
    assert option1 == option2, 'They are not `==`'
  end

  def test_two_options_with_same_keyword_and_arguments_are_eql
    option1 = Snort::RuleOption.new('msg', '"OHAI"')
    option2 = Snort::RuleOption.new('msg', '"OHAI"')
    assert option1.eql?(option2), 'They are not `eql?`'
  end

  def test_two_options_with_same_keyword_and_arguments_produce_same_hash
    option1 = Snort::RuleOption.new('msg', '"OHAI"')
    option2 = Snort::RuleOption.new('msg', '"OHAI"')
    assert_equal option1.hash, option2.hash
  end
  
  def test_options_hash
    strule = 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"test"; ' +
      'flow:to_server, established; '+
      'content:"GET"; http_method; ' +
      'content:"/private.php?"; nocase; http_uri; ' +
      'content:"id="; nocase; http_uri; ' +
      'content:"UNITED"; nocase; http_uri; ' +
      'content:"SELECTED"; nocase; http_uri; ' +
      'pcre:"/UNITED.+SELECTED/Ui"; ' +
      'reference:ref1; reference:ref2; reference:ref3; ' +
      'classtype:test-attack; sid:1234; rev:442;)'
    rule = Snort::Rule.parse(strule)
    assert_equal ["\"test\""], rule.options_hash["msg"][0].arguments
    assert_equal ["to_server, established"], rule.options_hash["flow"][0].arguments
    assert rule.options_hash["content"]
    assert_equal 5, rule.options_hash["content"].length
    assert_equal ['"/private.php?"', 'nocase', 'http_uri'], rule.options_hash["content"][1].arguments
    assert_equal 3, rule.options_hash["reference"].length
    assert_equal ["ref3"], rule.options_hash["reference"][2].arguments
    assert_nil rule.options_hash["xxxx"]
  end

end
