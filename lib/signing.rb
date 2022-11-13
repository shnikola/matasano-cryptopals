require_relative "hash_sha1"

module Signing

  def self.sha1_mac(key, message)
    HashSHA1.digest(key + message)
  end

  def self.sha1_mac_valid?(key, message, mac)
    sha1_mac(key, message) == mac
  end

end