require_relative "string_helpers"
require_relative "english"
require_relative "xor_crypter"

module XorHacker

  def self.break_single_byte_key(input)
    # XOR encryption with a single byte can be broken by decrypting with
    # every possible byte, and choosing whatever looks like english letters the most.

    key = (0..255).map(&:chr).max_by do |c|
      decrypted = XorCrypter.single_byte_decrypt(input, c)
      English.score(decrypted)
    end

    decrypted = XorCrypter.single_byte_decrypt(input, key)
    return [decrypted, key] if English.valid?(decrypted)
  end

  def self.break_repeating_key(input)
    # For repeating XOR keys, first we try to guess the blocksize by searching
    # for a size that gives the least distance between blocks (on average).

    blocksizes = guess_block_size(input, 3)

    blocksizes.filter_map do |blocksize|
      key, decrypted = break_repeating_key_with_size(input, blocksize)
      [decrypted, key] if key
    end
  end

  def self.break_repeating_key_with_size(input, blocksize)
    # We take the first byte of each block and use that as ciphertext for
    # single byte XOR. We do the same for the second byte, and so on.
    key = ""
    (0...blocksize).each do |i|
      ith_bytes = input.blocks(blocksize).map{|b| b[i]}.join
      _, c = break_single_byte_key(ith_bytes)
      return nil if c.nil?
      key << c
    end

    return key, XorCrypter.repeated_key_decrypt(input, key)
  end

  HAMMING_SAMPLE_COUNT = 4
  BLOCKSIZE_RANGE = (2..40)

  def self.guess_block_size(input, take)
    # Prefer blocksizes that have smaller Hamming distance between input blocks
    BLOCKSIZE_RANGE.sort_by do |size|
      average_hamming_distance(input, size)
    end.first(take)
  end


  def self.average_hamming_distance(str, blocksize)
    sampled_weights = []
    (0...HAMMING_SAMPLE_COUNT).each do |i|
      sampled_weights << hamming_distance(str.block(i, blocksize), str.block(i+1, blocksize)).to_f / blocksize
    end
    sampled_weights.sum / sampled_weights.count
  end

  def self.hamming_distance(str1, str2)
    (str1 ^ str2).unpack1("B*").count("1")
  end

end