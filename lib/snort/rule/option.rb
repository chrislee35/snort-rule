module Snort
  class RuleOption

    attr_reader :keyword, :arguments

    # @param [String] keyword
    # @param [String] arguments
    def initialize(keyword, arguments=nil)
      @keyword = keyword.to_s
      @arguments = arguments.to_s
    end

    def to_s
      output = @keyword
      output << ":#{@arguments}" unless @arguments.empty?
      output << ';'
      output
    end

    def ==(other)
      @keyword == other.keyword && @arguments == other.arguments
    end

    def eql?(other)
      self == other
    end

    def hash
      [@keyword, @arguments].hash
    end
  end
end