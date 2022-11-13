module English

  def self.valid?(text)
    score(text) > 0.9
  end

  def self.score(str)
    total_score = 0
    total_score += str.chars.grep(/[A-Za-z'.,\n -]/).count * 1.0
    total_score += str.chars.grep(/[0-9!";:\/]/).count * 0.8
    total_score / str.length
  end

end