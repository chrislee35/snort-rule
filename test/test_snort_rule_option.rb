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

end