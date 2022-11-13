require_relative "block_crypter"
require_relative "string_helpers"

module StreamCrypter

  def self.ctr_encrypt(input, key, nonce = 0)
    counter = 0
    packer = { 4 => "S<S<", 8 => "L<L<", 16 => "Q<Q<" }[key.size]
    input.blocks(key.size).map do |block|
      keystream = BlockCrypter.ecb_encrypt([nonce, counter].pack(packer), key, pad: false)
      counter += 1
      block ^ keystream[0, block.size]
    end.join
  end

  def self.ctr_decrypt(input, key, nonce = 0)
    ctr_encrypt(input, key, nonce)
  end

  def self.ctr_edit(ciphertext, key, nonce, offset, newtext)
    deciphered = ctr_decrypt(ciphertext, key, nonce)
    deciphered[offset, newtext.size] = newtext
    ctr_encrypt(deciphered, key, nonce)
  end

  def self.rng_encrypt(input, rng)
    input.bytes.map do |byte|
      random_byte = rng.get & 0xFF
      byte ^ random_byte
    end.pack('C*')
  end

  def self.rng_decrypt(input, rng)
    rng_encrypt(input, rng)
  end

end
