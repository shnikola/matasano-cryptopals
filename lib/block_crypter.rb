require "openssl"
require_relative "string_helpers"

module BlockCrypter

  def self.ecb_encrypt(input, key, pad: true)
    input = pkcs7_pad(input, key.size) if pad
    cipher = OpenSSL::Cipher.new('aes-128-ecb').encrypt
    cipher.key = key
    cipher.padding = 0
    cipher.update(input) + cipher.final
  end

  def self.ecb_decrypt(input, key, unpad: true)
    decipher = OpenSSL::Cipher.new('aes-128-ecb').decrypt
    decipher.key = key
    decipher.padding = 0
    output = decipher.update(input) + decipher.final
    unpad ? pkcs7_unpad(output) : output
  end

  def self.cbc_encrypt(input, key, iv = nil)
    input = pkcs7_pad(input, key.size)
    prev_cipher_block = iv || "\x00"*key.size
    input.blocks(key.size).map do |plain_block|
      cipher_block = ecb_encrypt(plain_block ^ prev_cipher_block, key, pad: false)
      prev_cipher_block = cipher_block
      cipher_block
    end.join
  end

  def self.cbc_decrypt(input, key, iv = nil)
    prev_cipher_block = iv || "\x00"*key.size
    input.blocks(key.size).map do |cipher_block|
      plain_block = ecb_decrypt(cipher_block, key, unpad: false) ^ prev_cipher_block
      prev_cipher_block = cipher_block
      plain_block
    end.join
  end

  def self.pkcs7_pad(input, blocksize)
    padding_size = blocksize - input.blocks(blocksize).last.length
    if padding_size > 0
      input + padding_size.chr * padding_size
    else
      input + blocksize.chr * blocksize
    end
  end

  def self.pkcs7_unpad(input)
    pad_size = input[-1].ord
    input[0...-pad_size]
  end

  def self.pkcs7_valid?(input)
    pad_size = input[-1].ord
    return false if pad_size > input.size
    input[-pad_size..].chars.all?{|c| c == input[-1]}
  end

end