require_relative "lib/string_helpers"
require_relative "lib/stream_crypter"
require_relative "lib/stream_hacker"
require_relative "lib/rng_mersenne"
require_relative "lib/rng_hacker"

# Implement CTR, the stream cipher mode
def challenge_18
  input = String.from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
  key = "YELLOW SUBMARINE"
  p StreamCrypter.ctr_decrypt(input, key)
end

# Break fixed-nonce CTR mode using substitutions
def challenge_19
  random_key = Random.bytes(16)
  inputs = File.readlines("files/19.txt", chomp: true).map{|l| String.from_base64(l) }
  cipher_inputs = inputs.map{|i| StreamCrypter.ctr_encrypt(i, random_key) }

  p StreamHacker.break_nonceless_ctr_by_guessing(cipher_inputs)
end

# Break fixed-nonce CTR statistically
def challenge_20
  random_key = Random.bytes(16)
  inputs = File.readlines("files/20.txt", chomp: true).map{|l| String.from_base64(l) }
  cipher_inputs = inputs.map{|i| StreamCrypter.ctr_encrypt(i, random_key) }

  puts StreamHacker.break_nonceless_ctr_statistically(cipher_inputs)
end

# Implement the MT19937 Mersenne Twister RNG
def challenge_21
  rng = RngMersenne.seed(41)
  10.times { p rng.get }
end

# Crack an MT19937 seed
def challenge_22
  sleep(5 + 10 * Random.rand)
  random_seed = Time.now.to_i
  sleep(5 + 10 * Random.rand)

  number = RngMersenne.seed_with(random_seed).get
  p "Seeded with #{random_seed}"

  p RngHacker.crack_mt19937_timestamp_seed(number, (Time.now.to_i - 60)..Time.now.to_i)
end

# Clone an MT19937 RNG from its output
def challenge_23
  random_seed = (Random.rand * 10000).to_i
  rng = RngMersenne.seed_with(random_seed)

  rng_clone = RngHacker.clone_mt19937(rng)
  p rng.take(100)
  p rng_clone.take(100)
end

# Create the MT19937 stream cipher and break it
def challenge_24
  random_seed = Random.rand(0..0xFFFF)
  rng = RngMersenne.seed_with(random_seed)
  p "Seeded with #{random_seed}"

  known_input = "AAAAAAAAA"
  random_prefix = Random.bytes(rand(5..10))

  cipher = StreamCrypter.rng_encrypt(random_prefix + known_input, rng)

  p RngHacker.break_mt19937_stream_cipher(cipher, known_input)
end

# Break "random access read/write" AES CTR
def challenge_25
  plaintext = File.read("files/25.txt")
  random_key = Random.bytes(16)
  nonce = 42
  ciphertext = StreamCrypter.ctr_encrypt(plaintext, random_key, nonce)

  p StreamHacker.break_ctr_with_edit(ciphertext) { |input, offset, plain|
    StreamCrypter.ctr_edit(input, random_key, nonce, offset, plain)
  }
end

# CTR bitflipping
def challenge_26
  random_key = Random.bytes(16)
  nonce = 42
  cipher_admin = StreamHacker.manipulate_known_ctr_encode { |i| StreamCrypter.ctr_encrypt(i, random_key, nonce) }
  p StreamCrypter.ctr_decrypt(cipher_admin, random_key, nonce)
end