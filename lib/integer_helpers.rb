class Integer

  # Convert int into a byte array, without leading zeroes
  def bytes
    [self].pack("L>").unpack("C*").drop_while{|b| b == 0 }
  end

  def to_i32
    self & 0xFFFFFFFF
  end

  def left_rotate(n)
    (self << n).to_i32 | (self >> (32 - n))
  end

end