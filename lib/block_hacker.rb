require_relative "block_crypter"

module BlockHacker

  def self.detect_block_size(&encrypter)
    # Increase input size until the output adds another block
    first_size = encrypter.call("A").size
    (2..).each do |i|
      next_size = encrypter.call("A" * i).size
      return next_size - first_size if next_size > first_size
    end
  end

  def self.detect_encryption(&encrypter)
    blocksize = detect_block_size(&encrypter)

    # Use a long, repetitive input. If it's ECB, it will give repeated blocks
    cipher_blocks = encrypter.call("A" * 128).blocks(blocksize)
    cipher_blocks.size > cipher_blocks.uniq.size ? "ECB" : "CBC"
  end

  # ======= Breaking ECB =======

  def self.break_ecb_suffix(&encrypter)
    blocksize = detect_block_size(&encrypter)
    return "Only works for ECB" if detect_encryption(&encrypter) != "ECB"

    suffix = ""

    loop do
      char = get_next_suffix_byte(suffix, blocksize, &encrypter)
      if char
        suffix += char
      else
        return BlockCrypter.pkcs7_unpad(suffix)
      end
    end
  end

  def self.get_next_suffix_byte(suffix, blocksize, &encrypter)
    # Craft input so it's exactly 1 byte short of a block, e.g. "AAAAAAA_".
    # The last byte of the input will be the first byte of the suffix.
    input = "A" * (blocksize - (suffix.size % blocksize) - 1)
    solved_blocks = suffix.size / blocksize

    # Get cipher for 1 byte short block
    cipherblock = encrypter.call(input).block(solved_blocks, blocksize)

    # Try out all possible combinations ("AAAAAAAA", "AAAAAAAB", "AAAAAAAC"...)
    # and see which one returns the same cipherblock
    (1..127).map(&:chr).each do |c|
      ciphertry = encrypter.call(input + suffix + c).block(solved_blocks, blocksize)
      return c if ciphertry == cipherblock
    end

    nil
  end

  def self.manipulate_known_ecb_encode(&encrypter)
    create_cookie = lambda{ |email| "email=#{email.tr('&=', '')}&uid=10&role=user" }
    blocksize = detect_block_size(&encrypter)

    # First we generate a cipher where "email=___&uid=10&role=" is exactly blocksize.
    # "user" will then occupy the last block.
    email_pad = "_" * (2*blocksize - "email=".size - "&uid=10&role=".size)
    cookie = create_cookie.call(email_pad)

    roleless_block = encrypter.call(cookie)[...-blocksize] # Discard the last block with "user"

    # Then we generate a cipher where "admin" will occupy the block for itself,
    # and just pad it PKCS7
    email_part = "_" * (blocksize - "email=".size)
    admin_part = BlockCrypter.pkcs7_pad("admin", blocksize)
    cookie = create_cookie.call(email_part + admin_part)

    admin_block = encrypter.call(cookie).block(1, blocksize) # Take the second block
    roleless_block + admin_block
  end

  def self.break_ecb_prefix_and_suffix(&encrypter)
    blocksize = detect_block_size(&encrypter)
    prefix_size = detect_prefix_size(blocksize, &encrypter)

    # We want to pad out the prefix to a full block and cut it out:
    prefix_pad_size = blocksize - (prefix_size % blocksize)
    prefix_pad = "A"*prefix_pad_size
    cutout_size = prefix_size + prefix_pad_size

    encrypter_without_prefix = lambda do |input|
      encrypter.call(prefix_pad + input)[cutout_size..]
    end

    break_ecb_suffix(&encrypter_without_prefix)
  end

  def self.detect_prefix_size(blocksize, &encrypter)
    cipher_basic = encrypter.call("")
    cipher_input = encrypter.call("A")

    # Blocks that contain only the prefix will remain the same. The block containing
    # the prefix end is the first one that changes when adding input.
    #
    # PPPP PPPP PSSS SSSS
    # PPPP PPPP PASS SSSS

    block_count = cipher_basic.size / blocksize
    end_block_i = (0...block_count).each do |i|
      if cipher_basic.block(i, blocksize) != cipher_input.block(i, blocksize)
        break i
      end
    end

    prefix_size = end_block_i * blocksize

    # To calculate the prefix length with that last block, we add inputs of different lengths
    # until that block stops changing
    #
    # PPPP PPPP PSSS SSSS
    # PPPP PPPP PASS SSSS
    # PPPP PPPP PAAS SSSS
    # PPPP PPPP PAAA SSSS
    # PPPP PPPP PAAA ASSS

    end_block_variants = []
    (1..blocksize+1).each do |inputsize|
      end_block_variants << encrypter.call("A" * inputsize).block(end_block_i, blocksize)
    end

    pad_size = end_block_variants.each_with_index do |block, i|
      break i + 1 if block == end_block_variants[i+1]
    end

    prefix_size += blocksize - pad_size

    prefix_size
  end

  # ======= Breaking CBC =======

  def self.manipulate_known_cbc_encode(&encrypter)
    create_cookie = lambda{|i| "comment1=cooking%20MCs;userdata=#{i.tr(';=', '')};comment2=%20like%20a%20pound%20of%20bacon" }
    blocksize = detect_block_size(&encrypter)

    # The input we want to sneak into the cookie contains ; and =, which will not pass the encoding.
    # So we flip the last bit of these characters.
    input = ";admin=true"
    [0, 6].each{ |i| input[i] ^= 1.chr }

    # input is now ":admin<true", which will pass the encoding.
    cipher = encrypter.call(create_cookie.call(input))

    # Flipping the bits in block 1 of ciphertext will cause the same bits in block 2
    # to be flipped during encryption (and the block 1 to become scrambled):
    #
    # 11111111 00000000 -> Plain text
    # 01100010 01110100 -> Cipher text
    # 01100011 01110100 -> Cipher with flipped last bit of block 1
    # 10101101 00000001 -> Encrypted text: block 1 scrambled, block 2 last bit flipped

    blocks = cipher.blocks(blocksize)
    flippy_block = blocks[1]
    [0, 6].each{ |i| flippy_block[i] ^= 1.chr }

    blocks.join
  end

  def self.break_cbc_with_padding_validation(cipher, blocksize, &validator)
    # We can break a ciphertext of a block using its preceding blocks and a padding validator.

    blocks = cipher.blocks(blocksize)
    plain_blocks = []

    (0...blocks.count).each do |i|
      if i == 0
        # The first block doesn't have a preceding block, so we prepend a (known) IV to act like one.
        plain_blocks << break_cbc_block_with_padding_validation("\x00"*blocksize, blocks[0], &validator)
      else
        plain_blocks << break_cbc_block_with_padding_validation(blocks[...i].join, blocks[i], &validator)
      end
    end

    plain_blocks.join
  end

  def self.break_cbc_block_with_padding_validation(cyph_prefix, cyph_block, &validator)
    # The changes in cyph_prefix[] will influence the changes in plain_block[].
    # Specifically, every change in cyph_prefix[] will be xored in plain_block[] in the same position.

    # We will use the validator to find which change to cyph_prefix[] will give us
    # a 0x01 (which is valid padding) in the end of plain_block[].

    plain_block = [nil] * cyph_block.size
    changed_byte = [nil] * cyph_block.size

    changed_byte[-1] = (0..255).map(&:chr).each do |ch|
      new_prefix = cyph_prefix[..-2] + ch
      next if !validator.call(new_prefix + cyph_block)
      # 0x02 0x02 (or 0x03 0x03 0x03) is also a valid padding which we do not care about.
      # To make sure we have 0x01, we try the same ending with a different prefix, which will only work for 0x01.
      new_prefix_with_diff = cyph_prefix[..-3] + (cyph_prefix[-2] ^ 1.chr) + ch
      next if !validator.call(new_prefix_with_diff + cyph_block)
      break ch
    end

    # changed_byte is a change in cyph_prefix[] that produces 0x01 as the last byte.
    # plain_block[i] ^ cyph_prefix[i] ^ changed_byte = 0x01

    plain_block[-1] = cyph_prefix[-1] ^ changed_byte[-1] ^ 1.chr
    # We can do the same for the rest of the bytes in plain_block, using endings
    # 0x02 0x02, 0x03 0x03 0x03, and so on.

    # E.g. to calculate the changed_byte[-4] we construct the following ciphertext:
    # cyph_prefix[..-5] +
    # ch +
    # changed_byte[-3] ^ 3.chr ^ 4.chr +
    # changed_byte[-2] ^ 2.chr ^ 4.chr +
    # changed_byte[-1] ^ 1.chr ^ 4.chr +
    # cyph_block

    (2..cyph_block.size).each do |i|
      changed_byte[-i] = (0..255).map(&:chr).each do |ch|
        new_prefix = cyph_prefix[..-i-1] + ch + (i-1).downto(1).map{|j| changed_byte[-j] ^ j.chr ^ i.chr }.join
        next if !validator.call(new_prefix + cyph_block)
        break ch
      end
      plain_block[-i] = cyph_prefix[-i] ^ changed_byte[-i] ^ i.chr
    end

    plain_block.join
  end

  def self.break_cbc_when_iv_is_key(cipher, blocksize, &decrypter)
    cipher_blocks = cipher.blocks(blocksize)

    # If applications leak invalid deciphers to attackers (for example, in an error message),
    # we can modify the cipher and trick the app to reveal the IV.
    # This is usually not a problem, but it's pretty bad if IV is set to be the same as KEY.

    # We modify the first 3 cipher blocks to be:
    # [C1, 0, C1]
    # The deciphered blocks will be:
    # [IV ^ P1, _, P1 ^ 0],
    # which means that by XORing the first and third deciphered block we get
    # IV ^ P1 ^ P1 ^ 0 = IV (KEY)

    init_block = cipher_blocks[0]
    zero_block = 0.chr * blocksize
    modified_cipher = ([init_block, zero_block, init_block] + cipher_blocks[3..]).join

    decipher_leak = decrypter.call(modified_cipher)
    key = decipher_leak.block(0, blocksize) ^ decipher_leak.block(2, blocksize)

    [key, BlockCrypter.cbc_decrypt(cipher, key, key)]
  end

end