require_relative "lib/string_helpers"
require_relative "lib/signing"
require_relative "lib/signing_hacker"

# Implement a SHA-1 keyed MAC
def challenge_28
  random_key = Random.bytes(16)
  message = "Hello world"
  mac = p Signing.sha1_mac(random_key, message)
  p Signing.sha1_mac_valid?(random_key, message, mac)
end

# Break a SHA-1 keyed MAC using length extension
def challenge_29
  random_key = Random.bytes(rand(5..10))
  message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

  original_mac = p Signing.sha1_mac(random_key, message)

  p SigningHacker.break_sha1_mac_by_extension(message, original_mac) { |msg, mac|
    Signing.sha1_mac_valid?(random_key, msg, mac)
  }
end