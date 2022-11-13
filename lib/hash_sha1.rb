require_relative "integer_helpers"

class HashSHA1

  K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6].freeze
  F = [
    proc { |b, c, d| (b & c) | (b.^(0xffffffff) & d) },
    proc { |b, c, d| b ^ c ^ d },
    proc { |b, c, d| (b & c) | (b & d) | (c & d) },
    proc { |b, c, d| b ^ c ^ d }
  ].freeze

  def self.digest(str)
    input = str.bytes
    input += calculate_padding(input.size)

    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]

    loop do
      block = input.shift(64)
      break if block.empty?
      state = process_block(block, state)
    end

    state.pack('N5').unpack1('H*')
  end

  def self.calculate_padding(input_size)
    start = [0x80]
    size_part = (input_size * 8).bytes
    zeroes = [0] * (64 - (input_size + start.size + size_part.size) % 64)

    start + zeroes + size_part
  end

  def self.process_block(block, state)
    w = block.pack('C*').unpack('N16')

    (16..79).each do |t|
      w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).left_rotate(1)
    end

    a, b, c, d, e = state
    t = 0
    4.times do |i|
      20.times do
        temp = (a.left_rotate(5) + F[i][b, c, d] + e + w[t] + K[i]).to_i32
        a, b, c, d, e = temp, a, b.left_rotate(30), c, d
        t += 1
      end
    end

    [a, b, c, d, e].each_with_index do |x, i|
      state[i] = (state[i] + x).to_i32
    end

    state
  end

end