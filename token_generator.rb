require 'openssl'
require 'base64'

class Token

  APP_ID = 'your_app_id'.freeze
  DEV_KEY = 'your_dev_key'.freeze
  SEP = "\0".b.freeze
  EPOCH_SECONDS = 62167219200.freeze

  def initialize(user_name, expires, v_card_file = '')
    @type = 'provision'
    @key = DEV_KEY
    @jid = user_name + '@' + APP_ID
    @expires = expires
    @v_card = v_card_file
    unless v_card_file.empty?
      @v_card = File.read(v_card_file).strip
    end
  end

  def generate
    Base64.strict_encode64(serialize)
  end

  private

  def expires_at
    Time.now.to_i + @expires.to_i + EPOCH_SECONDS
  end

  def serialize
    body = [@type, @jid, expires_at, @v_card].join(SEP)
    mac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA384.new, @key, body)
    body + SEP + mac
  end
end
