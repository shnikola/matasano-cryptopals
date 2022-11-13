require_relative "rng_mersenne"
require_relative "stream_crypter"

module RngHacker

  def self.crack_mt19937_timestamp_seed(number, timerange)
    timerange.each do |t|
      return t if RngMersenne.seed_with(t).extract_number == number
    end
  end

  def self.clone_mt19937(rng)
    # The internal state of MT19937 consists of 624 values. On each get,
    # the next value is tempered to produce a number.

    # With access to the original RNG, we generate 624 outputs, and inverse
    # the tempering to get 624 internal state values.

    numbers = rng.take(624)
    RngMersenneClone.new(numbers)
  end

  class RngMersenneClone < RngMersenne
    def initialize(numbers)
      @index = N
      @mt = numbers.map {|n| untemper(n)}
    end

    def untemper(y)
      y = undo_rshift_xor(y, L)
      y = undo_lshift_xor(y, T, C)
      y = undo_lshift_xor(y, S, B)
      y = undo_rshift_xor(y, U)
      y.to_i32
    end

    # I'm not sure how this shift inverses work, but here they are.

    def undo_rshift_xor(v, offset)
      [1, 2, 4, 8, 16].each do |i|
        v = v ^ (v >> (offset * i))
      end
      v.to_i32
    end

    def undo_lshift_xor(value, offset, mask)
      chunk_mask = (1 << offset) - 1
      (0..32 / offset).each do |n|
        chunk = value >> (n * offset) & chunk_mask
        value ^= chunk << ((n + 1) * offset) & mask
      end
      value.to_i32
    end
  end

  def self.break_mt19937_stream_cipher(cipher, known_input)
    # We simply try out every possible 16-bit seed until we get our known plaintext part

    (0..0xFFFF).each do |seed|
      rng = RngMersenne.seed_with(seed)
      deciphered = StreamCrypter.rng_decrypt(cipher, rng)
      return seed if deciphered.include?(known_input)
    end
  end

end