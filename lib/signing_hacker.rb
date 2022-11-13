require_relative "integer_helpers"
require_relative "hash_sha1"

module SigningHacker

  def self.break_sha1_mac_by_extension(message, mac, &validator)
    # The weakness of SHA-1 is that you can use a given SHA-1(input)
    # to calculate SHA-1(input + suffix), even if you don't know the input.
    # In our case, input = KEY + message, and we don't know the KEY.

    suffix = ";admin=true"

    # To calculate the suffix hash, we just resume the SHA-1 state from the input hash:
    # ExtendableHashSHA1.resume(mac, suffix)

    # The only snag is that SHA-1 adds a padding to the end of the message before hashing it,
    # so our new message will need to be: message + original_padding + suffix.

    # The padding depends on the length of the input (key + message). We don't know
    # the key, so we try out all possible paddings for every key length.

    (1..32).each do |key_size|
      possible_padding = HashSHA1.calculate_padding(key_size + message.size).pack("C*")

      new_message = message + possible_padding + suffix

      # We now simulate the SHA-1 state after it hashes the key + original message + padding
      new_mac = ExtendableHashSHA1.resume(mac, suffix, key_size + message.size + possible_padding.size)

      # If the app confirms the MAC is valid, it means we have guessed the key size!
      return [new_message, new_mac] if validator.call(new_message, new_mac)
    end
  end

  class ExtendableHashSHA1 < HashSHA1
    def self.resume(from_hash, suffix, prior_size)
      input = suffix.bytes
      input += calculate_padding(prior_size + input.size)

      state = [from_hash].pack('H*').unpack('N5')

      loop do
        block = input.shift(64)
        break if block.empty?
        state = process_block(block, state)
      end

      state.pack('N5').unpack1('H*')
    end
  end

end