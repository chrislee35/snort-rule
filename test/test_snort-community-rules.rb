unless Kernel.respond_to?(:require_relative)
  module Kernel
    def require_relative(path)
      require File.join(File.dirname(caller[0]), path.to_str)
    end
  end
end

require_relative 'helper'

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
    rules = []
    File.open("test/community-rules/community.rules").each_line do |line|
      next unless line =~ /alert/
      begin
        rule = Snort::Rule.parse(line)
        if rule
          rules << rule
        end
      rescue ArgumentError => e
      rescue NoMethodError => e
      end
    end
    assert_equal 3127, rules.length
    assert_equal 2522, rules.count{|r| ! r.enabled}
    assert_equal 605, rules.count{|r| r.enabled}
  end
end