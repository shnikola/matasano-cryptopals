require_relative "string_helpers"

module XorCrypter

  def self.single_byte_encrypt(input, char)
    key = char * input.size
    input ^ key
  end

  def self.single_byte_decrypt(input, char)
    single_byte_encrypt(input, char)
  end

  def self.repeated_key_encrypt(input, key)
    key = (key * input.size)[0, input.size]
    input ^ key
  end

  def self.repeated_key_decrypt(input, key)
    repeated_key_encrypt(input, key)
  end

end
