# rake warned with suggestion to add gem 'minitest' ahead of require 'minitest/autorun'
gem 'minitest'
require 'minitest/autorun'
require 'minitest/pride'
require File.expand_path('../../lib/snort/rule.rb', __FILE__)
