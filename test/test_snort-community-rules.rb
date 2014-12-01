unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'
require 'pp'

class TestSnortCommunityRules < Minitest::Test
  def setup
    destination = "test"
    if not File.exist?("#{destination}/community-rules/community.rules")
      require 'open-uri'
      require 'zlib'
      require 'rubygems/package'
      require 'fileutils'
      
      url = "https://www.snort.org/downloads/community/community-rules.tar.gz"
      puts "downloading #{url} to #{destination}/community-rules/community.rules"
      tarfile = open(url)
      
      # un-gzips the given IO, returning the
      # decompressed version as a StringIO
      z = Zlib::GzipReader.new(tarfile)
      unzipped = StringIO.new(z.read)
      z.close
      tarfile.close
      Gem::Package::TarReader.new unzipped do |tar|
        tar.each do |tarfile|
          destination_file = File.join destination, tarfile.full_name
          if tarfile.directory?
            FileUtils.mkdir_p destination_file
          else
            destination_directory = File.dirname(destination_file)
            FileUtils.mkdir_p destination_directory unless File.directory?(destination_directory)
            File.open destination_file, "wb" do |f|
              f.print tarfile.read
            end
          end
        end 
      end
    end
  end
  
  def test_complete_rules_file
    rules = Snort::RuleSet::from_file("test/community-rules/community.rules")
    assert_equal 3127, rules.length
    assert_equal 2522, rules.count{|r| ! r.enabled}
    assert_equal 605, rules.count{|r| r.enabled}
    rules.disable_all
    count = 0
    rules.each do |rule|
      count += 1
    end
    assert_equal 3127, count
    assert_equal 0, rules.count{|r| r.enabled}
    assert_equal 3127, rules.count{|r| ! r.enabled}
    rules.enable_all
    assert_equal 3127, rules.count{|r| r.enabled}
    assert_equal 0, rules.count{|r| ! r.enabled}
    rules.disable do |r|
      r.get_option_first("msg").match(/^"MALWARE\-CNC/)
    end
    assert_equal 392, rules.count{|r| ! r.enabled}
    assert_equal 2735, rules.count{|r| r.enabled}
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
    assert_equal 343, rules.count{|r| ! r.enabled}
    assert_equal 2726, rules.count{|r| r.enabled}
    rules.delete_all
    assert_equal 0, rules.length
    assert_equal 0, rules.count{|r| r.enabled}
    assert_equal 0, rules.count{|r| ! r.enabled}    
  end
  
  # def test_ruleset_load_from_url
  #   rules = Snort::RuleSet::from_file("http://test.com/community.rules")
  #   assert_equal 3127, rules.length
  #   assert_equal 2522, rules.count{|r| ! r.enabled}
  #   assert_equal 605, rules.count{|r| r.enabled}
  # end
  
  def test_writing_file
    rules = Snort::RuleSet::from_file("test/community-rules/community.rules")
    assert_equal 3127, rules.length
    assert_equal 2522, rules.count{|r| ! r.enabled}
    assert_equal 605, rules.count{|r| r.enabled}
    rules.to_file("test/community-rules/community.rules.test")
    assert File.exist?("test/community-rules/community.rules.test")
    total = enabled = disabled = 0
    open("test/community-rules/community.rules.test", 'r').each_line do |l|
      if l =~ /^(#)?\s*(alert|log|pass|activate|dynamic|drop|reject|sdrop)/
        total += 1
        if l =~ /^#/
          disabled += 1
        else
          enabled += 1
        end
      end
    end
    assert_equal 3127, total
    assert_equal 2522, disabled
    assert_equal 605, enabled
  end
    
end