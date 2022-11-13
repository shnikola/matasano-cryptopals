require_relative "lib/string_helpers"
require_relative "lib/xor_crypter"
require_relative "lib/xor_hacker"

# Convert hex to base64
def challenge_1
  input = String.from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
  p input.to_base64
end

# Fixed XOR
def challenge_2
  input1 = String.from_hex("1c0111001f010100061a024b53535009181c")
  input2 = String.from_hex("686974207468652062756c6c277320657965")
  p (input1 ^ input2).to_hex
end

# Single-byte XOR cipher
def challenge_3
  input = String.from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  p XorHacker.break_single_byte_key(input)
end

# Detect single-character XOR
def challenge_4
  File.readlines("files/4.txt", chomp: true).each do |l|
    input = String.from_hex(l)
    output, key = XorHacker.break_single_byte_key(input)
    p [output, key] if output
  end
end

# Implement repeating-key XOR
def challenge_5
  input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
  p XorCrypter.repeated_key_encrypt(input, "ICE").to_hex
end

# Break repeating-key XOR
def challenge_6
  input = String.from_base64(File.read("files/6.txt"))
  p XorHacker.break_repeating_key(input)
end
