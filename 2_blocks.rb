require_relative "lib/string_helpers"
require_relative "lib/block_crypter"
require_relative "lib/block_hacker"

# Decrypt AES in ECB mode
def challenge_7
  input = String.from_base64(File.read("files/7.txt"))
  p BlockCrypter.ecb_decrypt(input, "YELLOW SUBMARINE")
end

# Detect AES in ECB mode
def challenge_8
  lines = File.readlines("files/8.txt", chomp: true).map{|l| String.from_hex(l) }
  lines.each do |line|
    p line.to_hex if line.blocks(16).uniq.count != line.blocks(16).count
  end
end

# Implement PKCS#7 padding
def challenge_9
  p BlockCrypter.pkcs7_pad("YELLOW SUBMARINE", 20)
end

# Implement CBC mode
def challenge_10
  input = String.from_base64(File.read("files/10.txt"))
  p BlockCrypter.cbc_decrypt(input, "YELLOW SUBMARINE")
end

# An ECB/CBC detection oracle
def challenge_11
  random_key = Random.bytes(16)
  prefix = Random.bytes(rand(5..10))
  suffix = Random.bytes(rand(5..10))

  if rand(2) == 0
    enc = BlockHacker.detect_encryption { |i| BlockCrypter.ecb_encrypt(prefix + i + suffix, random_key)}
    p "Detected #{enc} for ECB"
  else
    enc = BlockHacker.detect_encryption { |i| BlockCrypter.cbc_encrypt(prefix + i + suffix, random_key)}
    p "Detected #{enc} for CBC"
  end
end

# Byte-at-a-time ECB decryption (Simple)
def challenge_12
  random_key = Random.bytes(16)
  mystery_suffix = String.from_base64(File.read("files/12.txt"))

  p BlockHacker.break_ecb_suffix { |i| BlockCrypter.ecb_encrypt(i + mystery_suffix, random_key) }
end

# ECB cut-and-paste
def challenge_13
  random_key = Random.bytes(16)

  cipher_admin = BlockHacker.manipulate_known_ecb_encode { |i| BlockCrypter.ecb_encrypt(i, random_key) }
  p BlockCrypter.ecb_decrypt(cipher_admin, random_key)
end

# Byte-at-a-time ECB decryption (with prefix)
def challenge_14
  random_key = Random.bytes(16)
  random_prefix = Random.bytes(rand(1..40))
  mystery_suffix = String.from_base64(File.read("files/12.txt"))

  p BlockHacker.break_ecb_prefix_and_suffix { |i| BlockCrypter.ecb_encrypt(random_prefix + i + mystery_suffix, random_key) }
end

# PKCS#7 padding validation
def challenge_15
  p BlockCrypter.pkcs7_valid?("ICE ICE BABY\x04\x04\x04\x04")
  p BlockCrypter.pkcs7_valid?("ICE ICE BABY\x05\x05\x05\x05")
end

# CBC bitflipping attacks
def challenge_16
  random_key = Random.bytes(16)
  cipher_admin = BlockHacker.manipulate_known_cbc_encode { |i| BlockCrypter.cbc_encrypt(i, random_key) }
  p BlockCrypter.cbc_decrypt(cipher_admin, random_key)
end

# The CBC padding oracle
def challenge_17
  random_key = Random.bytes(16)
  input = String.from_base64(File.readlines("files/17.txt", chomp: true).sample)
  cipher = BlockCrypter.cbc_encrypt(input, random_key)

  p BlockHacker.break_cbc_with_padding_validation(cipher, 16) { |i|
    BlockCrypter.pkcs7_valid?(BlockCrypter.cbc_decrypt(i, random_key))
  }
end

# Recover the key from CBC with IV=Key
def challenge_27
  random_key = Random.bytes(16)
  input = File.read("files/25.txt")
  cipher = BlockCrypter.cbc_encrypt(input, random_key, random_key)

  p BlockHacker.break_cbc_when_iv_is_key(cipher, 16) { |i|
    deciphered = BlockCrypter.cbc_decrypt(i, random_key, random_key)
    # Let's say the receiver prints the deciphered text if it contains non-ascii chars
    deciphered if !deciphered.ascii_only?
  }
end