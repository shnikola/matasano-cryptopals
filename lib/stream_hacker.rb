require_relative "english"
require_relative "xor_hacker"

module StreamHacker

  def self.break_nonceless_ctr_by_guessing(cipher_inputs)
    outputs = cipher_inputs.map{ |i| "_" * i.length }

    # CTR is not using a nonce, meaning that all the keystreams are the same.
    # Having multiple xor ciphers with same key allows us to use frequency analysis or substitution.

    # We pick a common english trigram that should be in the plaintexts.

    try_ctr_guess_with_ciphers(cipher_inputs, "and", outputs)
    try_ctr_guess_with_ciphers(cipher_inputs, "the", outputs)
    try_ctr_guess_with_ciphers(cipher_inputs, " the ", outputs)
    # puts outputs

    # # After guessing a part, deduce other possible words and so on.
    try_ctr_guess_with_ciphers(cipher_inputs, "century", outputs)
    try_ctr_guess_with_ciphers(cipher_inputs, "changed", outputs)
    # puts outputs

    outputs
  end

  def self.try_ctr_guess_with_ciphers(cipher_inputs, plain_guess, outputs)
    partsize = plain_guess.size

    # We will xor this with every cipher input on every position to get possible keystream parts.
    # CIPHERTEXT ^ PLAINTEXT = KEYSTREAM

    cipher_inputs.each do |input|
      (0...input.length - partsize).each do |i|
        key_guess = input[i, partsize] ^ plain_guess

        # We check if the key part is valid by applying it to other ciphertexts.
        # CIPHERTEXT ^ KEYSTREAM = PLAINTEXT
        # (Some ciphers may be too short for this, so we ignore them)

        deciphers = cipher_inputs.map do |cipher|
          cipher_part = cipher[i, partsize].to_s
          if cipher_part.size > 1
            cipher_part ^ key_guess[0, cipher_part.size]
          else
            nil
          end
        end

        # Skip guess if there are not enough inputs to be sure
        next if deciphers.count{|d| !d.nil? } <= 2
        # Skip guess if there are invalid deciphers.
        next if deciphers.any?{|d| d && !English.valid?(d) }

        # Otherwise, apply the valid deciphers to their positions
        deciphers.each_with_index{ |d, j| outputs[j][i, partsize] = d if d }
      end
    end
  end

  def self.break_nonceless_ctr_statistically(cipher_inputs)

    # CTR is not using a nonce, meaning that all the keystreams are the same.
    # We can treat the collection of ciphertexts as a repeating-key xor:

    keysize = cipher_inputs.map(&:size).min
    same_length_ciphers = cipher_inputs.map{|i| i[0, keysize]}

    _, plain = XorHacker.break_repeating_key_with_size(same_length_ciphers.join, keysize)
    plain.blocks(keysize)
  end

  def self.break_ctr_with_edit(ciphertext, &editor)

    # A simple approach is to edit the first character, trying every possible byte, until we get the same
    # cipher. Then repeat it for next character, and so on.

    # plaintext = ""
    # (0...ciphertext.size).each do |i|
    #   plain_char = (0..255).map(&:chr).find{ |c| editor.call(ciphertext, i, c) == ciphertext }
    #   plaintext << plain_char
    # end
    # plaintext

    # An even simpler approach utilizes that CRT with fixed always XORs with same keystream:
    # PLAINTEXT ^ KEYSTREAM = CIPHERTEXT, from which follows:
    # PLAINTEXT = CIPHERTEXT ^ KEYSTREAM

    # We use the edit to encrypt a new known plain text with the same length.
    # NEW_PLAINTEXT ^ KEYSTREAM = NEW_CIPHERTEXT, from which follows:
    # KEYSTREAM = NEW_PLAINTEXT ^ NEW_CIPHERTEXT, and finally:
    # PLAINTEXT = CIPHERTEXT ^ NEW_PLAINTEXT ^ NEW_CIPHERTEXT

    new_plaintext = "A" * ciphertext.size
    new_ciphertext = editor.call(ciphertext, 0, new_plaintext)

    ciphertext ^ new_plaintext ^ new_ciphertext
  end

  def self.manipulate_known_ctr_encode(&encrypter)
    create_cookie = lambda{|i| "comment1=cooking%20MCs;userdata=#{i.tr(';=', '')};comment2=%20like%20a%20pound%20of%20bacon" }

    # The input we want to sneak into the cookie contains ; and =, which will not pass the encoding.
    # So we flip the last bit of these characters.
    input = ";admin=true"
    [0, 6].each{ |i| input[i] ^= 1.chr }

    # input is now ":admin<true", which will pass the encoding.
    cipher = encrypter.call(create_cookie.call(input))

    # CTR is just using a fixed keystream and XORing into ciphertext. We can just flip the bits of the
    # ciphertext and this will change the deciphered plaintext.
    cipher[32] ^= 1.chr
    cipher[38] ^= 1.chr

    cipher
  end

end