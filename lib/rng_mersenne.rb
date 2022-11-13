require_relative "integer_helpers"

class RngMersenne
  # MT19937 Mersenne Twister RNG

  W, N, M, R = [32, 624, 397, 31]
  A = 0x9908B0DF
  U, D = [11, 0xFFFFFFFF]
  S, B = [7, 0x9D2C5680]
  T, C = [15, 0xEFC60000]
  L = 18
  F = 1812433253

  def self.seed_with(seed)
    new(seed)
  end

  def initialize(seed)
    @index = N
    @mt = Array.new(N, 0)
    @mt[0] = seed
    (1...N).each do |i|
      @mt[i] = (F * (@mt[i - 1] ^ (@mt[i - 1] >> (W - 2))) + i).to_i32
    end
  end

  # Extract a tempered value based on @mt[@index]
  def get
    twist if @index == N

    y = @mt[@index]
    y = y ^ ((y >> U) & D)
    y = y ^ ((y << S) & B)
    y = y ^ ((y << T) & C)
    y = y ^ (y >> L)

    @index += 1

    y.to_i32
  end

  def take(n)
    n.times.map{ get }
  end

  private

  LOWER_MASK = (1 << R) - 1 # The binary number with R 1's
  UPPER_MASK = (~LOWER_MASK) & ((1 << W) - 1) # Lowest W bits of ~LOWER_MASK

  def twist
    (0...N).each do |i|
      x = @mt[i] & UPPER_MASK + @mt[(i + 1) % N] & LOWER_MASK
      xA = x >> 1
      xA = xA ^ A if x % 2 != 0
      @mt[i] = @mt[(i + M) % N] ^ xA
    end

    @index = 0
  end

end