module Snort
  class RuleOption

    attr_reader :keyword, :arguments

    # @param [String] keyword
    # @param [String] arguments
    def initialize(keyword, arguments=nil)
      @keyword = keyword.to_s
      if arguments == nil
        @arguments = []
      elsif arguments.class == String or arguments.class == Integer
        @arguments = [arguments]
      elsif arguments.class == Array
        @arguments = arguments
      else
        raise "I don't know what to do with an argument of class #{arguments.class}"
      end
    end
    
    def add_argument(argument)
      @arguments << argument
    end

    def to_s
      return "#{@keyword};" if @arguments.length == 0
      "#{@keyword}:#{@arguments.join("; ")};"
    end
    
    def to_json(arg)
      return "\"#{@arguments.join("; ")}\""
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
