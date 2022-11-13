require "base64"

class String

  def self.from_hex(hex_string)
    hex_string.split.pack('H*')
  end

  def to_hex
    self.unpack1("H*")
  end

  def self.from_base64(base64_string)
    Base64.decode64(base64_string)
  end

  def to_base64
    Base64.strict_encode64(self)
  end

  def ^(other)
    raise "XOR different lengths: #{bytes.size} and #{other.bytes.size}" if bytes.size != other.bytes.size
    self.bytes.zip(other.bytes).map{|a, b| a ^ b}.pack('C*')
  end

  def blocks(length)
    chars.each_slice(length).map(&:join)
  end

  def block(i, length)
    blocks(length)[i]
  end

end