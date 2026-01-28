# name: digest-combined2
# about: (1) Append tracking params to internal links in digest emails + (2) reuse SAME email_id for open tracking pixel + postback after send
# version: 2.1
# authors: you

after_initialize do
  require_dependency "user_notifications"
  require "net/http"
  require "uri"
  require "cgi"
  require "time"
  require "securerandom"
  require "base64"

  begin
    require "nokogiri"
  rescue LoadError
    Nokogiri = nil
  end

  module ::DigestReport
    PLUGIN_NAME = "digest-combined2"

    # =========================
    # HARD-CODED SETTINGS (edit here)
    # =========================
    ENABLED = true

    ENDPOINT_URL = "https://ai.templetrends.com/digest_report.php"

    OPEN_TRACKING_ENABLED = true
    OPEN_TRACKING_PIXEL_BASE_URL = "https://ai.templetrends.com/digest_open.php"

    DEBUG_LOG = true

    APPEND_ISDIGEST_FIELD   = "isdigest"
    APPEND_USER_ID_FIELD    = "u"
    APPEND_EMAIL_B64_FIELD  = "dayofweek"
    APPEND_EMAIL_ID_FIELD   = "email_id"

    EMAIL_ID_FIELD              = "email_id"
    OPEN_TRACKING_USED_FIELD    = "open_tracking_used"

    TOPIC_IDS_FIELD             = "topic_ids"
    TOPIC_COUNT_FIELD           = "topic_ids_count"
    FIRST_TOPIC_ID_FIELD        = "first_topic_id"

    SUBJECT_FIELD               = "subject"
    SUBJECT_PRESENT_FLD         = "subject_present"

    FROM_EMAIL_FIELD            = "from_email"

    USER_ID_FIELD               = "user_id"
    USERNAME_FIELD              = "username"
    USER_CREATED_AT_FIELD       = "user_created_at_utc"

    SUBJECT_MAX_LEN  = 300
    FROM_MAX_LEN     = 200
    USERNAME_MAX_LEN = 200

    OPEN_TIMEOUT_SECONDS  = 3
    READ_TIMEOUT_SECONDS  = 3
    WRITE_TIMEOUT_SECONDS = 3

    JOB_RETRY_COUNT = 2
    # =========================

    def self.log(msg)
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.log_error(msg)
      Rails.logger.error("[#{PLUGIN_NAME}] #{msg}")
    rescue StandardError
    end

    def self.dlog(msg)
      return unless DEBUG_LOG
      log("DEBUG #{msg}")
    rescue StandardError
    end

    def self.dlog_error(msg)
      return unless DEBUG_LOG
      log_error("DEBUG #{msg}")
    rescue StandardError
    end

    def self.enabled?
      return false unless ENABLED
      return false if ENDPOINT_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.open_tracking_enabled?
      return false unless OPEN_TRACKING_ENABLED
      return false if OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip.empty?
      true
    rescue StandardError
      false
    end

    def self.safe_str(v, max_len)
      s = v.to_s.strip
      s = s[0, max_len] if s.length > max_len
      s
    rescue StandardError
      ""
    end

    def self.safe_iso8601(t)
      return "" if t.nil?
      begin
        tt = t.respond_to?(:utc) ? t.utc : t
        tt.iso8601
      rescue StandardError
        ""
      end
    end

    def self.header_val(message, key)
      v = message&.header&.[](key)
      v.to_s.strip
    rescue StandardError
      ""
    end

    def self.extract_email_body(message)
      return "" if message.nil?

      if message.respond_to?(:multipart?) && message.multipart?
        html = ""
        txt  = ""
        begin
          html = message.html_part&.body&.decoded.to_s
        rescue StandardError
          html = ""
        end
        begin
          txt = message.text_part&.body&.decoded.to_s
        rescue StandardError
          txt = ""
        end
        return html unless html.to_s.empty?
        return txt  unless txt.to_s.empty?
      end

      message.body&.decoded.to_s
    rescue StandardError
      ""
    end

    def self.first_recipient_email(message)
      raw = Array(message&.to).first.to_s.strip
      return "" if raw.empty?
      begin
        addr = Mail::Address.new(raw)
        return addr.address.to_s.strip
      rescue StandardError
        m = raw.match(/([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})/i)
        return m ? m[1].to_s.strip : raw
      end
    rescue StandardError
      ""
    end

    def self.encoded_email(user)
      email = user&.email.to_s
      return "" if email.empty?
      Base64.urlsafe_encode64(email, padding: false)
    end

    def self.random_20_digit_id
      digits = +""
      20.times { digits << SecureRandom.random_number(10).to_s }
      digits
    rescue StandardError
      t = (Time.now.to_f * 1000).to_i.to_s
      (t + "0" * 20)[0, 20]
    end

    # STRICT: we only accept the FIRST internal link that has BOTH u=... AND email_id=... (20 digits)
    # Returns { email_id: "", user_id: "" }
    def self.extract_tracking_from_message(message)
      hdr_email_id = header_val(message, "X-Digest-Report-Email-Id")
      hdr_user_id  = header_val(message, "X-Digest-Report-User-Id")

      body = extract_email_body(message)
      return { email_id: hdr_email_id, user_id: hdr_user_id } if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      base = Discourse.base_url.to_s

      parse_href = lambda do |href|
        return nil if href.to_s.strip.empty?
        h = href.to_s.strip
        return nil if h.start_with?("mailto:", "tel:", "sms:", "#")

        is_relative = h.start_with?("/")
        is_internal = !base.empty? && h.start_with?(base)
        return nil unless is_relative || is_internal

        begin
          uri = URI.parse(is_relative ? (base + h) : h)
        rescue URI::InvalidURIError
          return nil
        end

        params = {}
        URI.decode_www_form(uri.query || "").each { |k, v| params[k.to_s] = v.to_s }

        uid = params[APPEND_USER_ID_FIELD].to_s.strip
        return nil if uid.empty?

        eid = params[APPEND_EMAIL_ID_FIELD].to_s.strip
        # STRICT: require 20 digits
        return nil unless eid.match?(/\A\d{20}\z/)

        { email_id: eid, user_id: uid }
      end

      if Nokogiri
        begin
          doc = Nokogiri::HTML(body)
          doc.css("a[href]").each do |a|
            res = parse_href.call(a["href"])
            return res if res
          end
        rescue StandardError
        end
      end

      begin
        body.scan(/href="([^"]+)"/i).each do |m|
          res = parse_href.call(m[0])
          return res if res
        end
      rescue StandardError
      end

      # If no STRICT match found, fall back to headers (could still be blank)
      { email_id: hdr_email_id, user_id: hdr_user_id }
    rescue StandardError
      { email_id: "", user_id: "" }
    end

    # Keep your append logic the same, but also add email_id=20digits
    # Returns email_id used
    def self.rewrite_digest_links!(message, user)
      return "" if message.nil?

      html_part =
        if message.respond_to?(:html_part) && message.html_part
          message.html_part
        else
          message
        end

      body = html_part.body&.decoded
      return "" if body.nil? || body.empty?

      base = Discourse.base_url.to_s
      dayofweek_val = encoded_email(user)
      email_id_val  = random_20_digit_id

      if Nokogiri
        doc = Nokogiri::HTML(body)

        doc.css("a[href]").each do |a|
          href = a["href"].to_s.strip
          next if href.empty?

          next if href.start_with?("mailto:", "tel:", "sms:", "#")

          is_relative = href.start_with?("/")
          is_internal = !base.empty? && href.start_with?(base)
          next unless is_relative || is_internal

          next if href.include?("/email/unsubscribe") || href.include?("/my/preferences")

          begin
            uri = URI.parse(is_relative ? (base + href) : href)
          rescue URI::InvalidURIError
            next
          end

          next unless uri.scheme.nil? || uri.scheme == "http" || uri.scheme == "https"

          params = URI.decode_www_form(uri.query || "")

          params << [APPEND_ISDIGEST_FIELD, "1"] unless params.any? { |k, _| k == APPEND_ISDIGEST_FIELD }
          params << [APPEND_USER_ID_FIELD, user.id.to_s] unless params.any? { |k, _| k == APPEND_USER_ID_FIELD }

          if !dayofweek_val.empty?
            params << [APPEND_EMAIL_B64_FIELD, dayofweek_val] unless params.any? { |k, _| k == APPEND_EMAIL_B64_FIELD }
          end

          params << [APPEND_EMAIL_ID_FIELD, email_id_val] unless params.any? { |k, _| k == APPEND_EMAIL_ID_FIELD }

          uri.query = URI.encode_www_form(params)
          a["href"] = uri.to_s
        end

        html_part.body = doc.to_html

      else
        html_part.body = body.gsub(/href="(#{Regexp.escape(base)}[^"]*|\/[^"]*)"/) do
          url = Regexp.last_match(1)
          next %{href="#{url}"} if url.include?("#{APPEND_ISDIGEST_FIELD}=") ||
                                  url.include?("/email/unsubscribe") ||
                                  url.include?("/my/preferences")

          joiner = url.include?("?") ? "&" : "?"
          extra = +"#{APPEND_ISDIGEST_FIELD}=1&#{APPEND_USER_ID_FIELD}=#{user.id}"
          extra << "&#{APPEND_EMAIL_B64_FIELD}=#{dayofweek_val}" unless dayofweek_val.empty?
          extra << "&#{APPEND_EMAIL_ID_FIELD}=#{email_id_val}"

          %{href="#{url}#{joiner}#{extra}"}
        end
      end

      # Optional header stamp (does NOT change the "scan links first" rule)
      begin
        message.header["X-Digest-Report-Email-Id"] = email_id_val.to_s
        message.header["X-Digest-Report-User-Id"]  = user.id.to_s
      rescue StandardError
      end

      email_id_val.to_s
    rescue StandardError => e
      log_error("rewrite_digest_links! error err=#{e.class}: #{e.message}")
      ""
    end

    def self.extract_topic_ids_from_message(message)
      body = extract_email_body(message)
      return [] if body.to_s.empty?

      begin
        body = CGI.unescapeHTML(body.to_s)
      rescue StandardError
        body = body.to_s
      end

      urls =
        begin
          body.scan(%r{https?://[^\s"'<>()]+}i)
        rescue StandardError
          []
        end

      ids = []
      seen = {}

      urls.each do |raw|
        next if raw.to_s.empty?
        u = raw.to_s.gsub(/[)\].,;]+$/, "")

        uri = (URI.parse(u) rescue nil)
        next if uri.nil?

        path = uri.path.to_s
        next if path.empty?

        m = path.match(%r{/t/(?:[^/]+/)?(\d+)(?:/|$)}i)
        next if m.nil?

        tid = m[1].to_i
        next if tid <= 0
        next if seen[tid]

        seen[tid] = true
        ids << tid
      end

      ids
    rescue StandardError => e
      log_error("extract_topic_ids_from_message error err=#{e.class}: #{e.message}")
      []
    end

    def self.build_tracking_pixel_html(email_id:, user_id:, user_email:)
      base = OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip
      return "" if base.empty?

      q = {
        "email_id"   => email_id.to_s,
        "user_id"    => user_id.to_s,
        "user_email" => user_email.to_s
      }

      url =
        begin
          uri = URI.parse(base)
          existing = uri.query.to_s
          add = URI.encode_www_form(q)
          uri.query = existing.empty? ? add : "#{existing}&#{add}"
          uri.to_s
        rescue StandardError
          "#{base}?#{URI.encode_www_form(q)}"
        end

      %Q(<img src="#{CGI.escapeHTML(url)}" width="1" height="1" style="display:none!important;max-height:0;overflow:hidden" alt="" />)
    rescue StandardError
      ""
    end

    def self.message_already_has_pixel?(mail_message)
      b = extract_email_body(mail_message)
      return false if b.to_s.empty?
      b.include?(OPEN_TRACKING_PIXEL_BASE_URL.to_s.strip)
    rescue StandardError
      false
    end

    def self.inject_pixel_into_mail!(mail_message, pixel_html)
      return false if mail_message.nil?
      return false if pixel_html.to_s.empty?

      begin
        if mail_message.respond_to?(:multipart?) && mail_message.multipart?
          hp = mail_message.html_part rescue nil
          return false if hp.nil?

          html = (hp.body.decoded.to_s rescue "")
          return false if html.to_s.empty?

          new_html =
            if html.include?("</body>")
              html.sub("</body>", "#{pixel_html}</body>")
            else
              html + pixel_html
            end

          hp.body = new_html rescue nil
          return true
        end
      rescue StandardError => e
        dlog_error("inject: multipart path error err=#{e.class}: #{e.message}")
      end

      begin
        ct = (mail_message.content_type.to_s rescue "")
        return false unless ct.downcase.include?("text/html")

        html = (mail_message.body.decoded.to_s rescue "")
        return false if html.to_s.empty?

        new_html =
          if html.include?("</body>")
            html.sub("</body>", "#{pixel_html}</body>")
          else
            html + pixel_html
          end

        mail_message.body = new_html rescue nil
        return true
      rescue StandardError => e
        dlog_error("inject: non-multipart path error err=#{e.class}: #{e.message}")
      end

      false
    rescue StandardError => e
      dlog_error("inject: crash err=#{e.class}: #{e.message}")
      false
    end
  end

  # 1) Digest generation: append params to links (includes email_id)
  module ::DigestReportDigestPatch
    def digest(user, opts = {})
      super.tap do |message|
        ::DigestReport.rewrite_digest_links!(message, user)
      end
    end
  end

  class ::UserNotifications
    prepend ::DigestReportDigestPatch
  end

  # 2) BEFORE send: STRICT scan for first internal link with BOTH u= and email_id=20digits. Do NOT generate here.
  DiscourseEvent.on(:before_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      existing_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      if !existing_id.empty?
        ::DigestReport.dlog("before_email_send: already stamped email_id=#{existing_id} -> skip")
        next
      end

      tracking = ::DigestReport.extract_tracking_from_message(message)
      email_id = tracking[:email_id].to_s.strip
      uid_str  = tracking[:user_id].to_s.strip

      recipient = ::DigestReport.first_recipient_email(message)

      # If strict scan failed (email_id blank), we still won't break sending:
      # we fall back to user lookup + random id (but logs it clearly).
      if email_id.empty?
        ::DigestReport.log_error("STRICT SCAN FAILED: no link with u= and email_id=20digits found. Falling back to random email_id.")
        email_id = ::DigestReport.random_20_digit_id
      end

      if uid_str.empty? && !recipient.empty?
        begin
          u = User.find_by_email(recipient)
          uid_str = u ? u.id.to_s : ""
        rescue StandardError
          uid_str = ""
        end
      end
      uid = uid_str.to_i

      injected = false
      if ::DigestReport.open_tracking_enabled?
        if ::DigestReport.message_already_has_pixel?(message)
          ::DigestReport.dlog("before_email_send: pixel already present -> injected=true (treat as used)")
          injected = true
        else
          pixel = ::DigestReport.build_tracking_pixel_html(email_id: email_id, user_id: uid, user_email: recipient)
          injected = ::DigestReport.inject_pixel_into_mail!(message, pixel)
        end
      end

      open_used = injected ? "1" : "0"

      begin
        message.header["X-Digest-Report-Email-Id"] = email_id.to_s
        message.header["X-Digest-Report-Open-Tracking-Used"] = open_used
        message.header["X-Digest-Report-User-Id"] = uid.to_s
      rescue StandardError
      end

      ::DigestReport.dlog("before_email_send: strict_link_scan email_id=#{email_id} uid=#{uid} to=#{recipient.inspect} injected=#{injected} open_used=#{open_used}")
    rescue StandardError => e
      ::DigestReport.dlog_error("before_email_send error err=#{e.class}: #{e.message}")
    end
  end

  # 3) Postback job
  class ::Jobs::DigestReportPostback < ::Jobs::Base
    sidekiq_options queue: "low", retry: ::DigestReport::JOB_RETRY_COUNT

    def execute(args)
      begin
        return unless ::DigestReport.enabled?

        url = ::DigestReport::ENDPOINT_URL.to_s.strip
        uri = (URI.parse(url) rescue nil)
        if uri.nil? || !(uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS))
          ::DigestReport.log_error("Invalid ENDPOINT_URL #{url.inspect}")
          return
        end

        email_id = args[:email_id].to_s.strip
        email_id = ::DigestReport.random_20_digit_id if email_id.empty?

        open_tracking_used = args[:open_tracking_used].to_s.strip
        open_tracking_used = "0" unless open_tracking_used == "1"

        user_email = args[:user_email].to_s.strip

        subject = ::DigestReport.safe_str(args[:subject], ::DigestReport::SUBJECT_MAX_LEN)
        subject_present = subject.empty? ? "0" : "1"

        from_email = ::DigestReport.safe_str(args[:from_email], ::DigestReport::FROM_MAX_LEN)

        user_id  = args[:user_id].to_s
        username = ::DigestReport.safe_str(args[:username], ::DigestReport::USERNAME_MAX_LEN)
        user_created_at_utc = args[:user_created_at_utc].to_s

        incoming_ids = Array(args[:topic_ids]).map { |x| x.to_i }
        seen = {}
        topic_ids_ordered = []
        incoming_ids.each do |tid|
          next if tid <= 0
          next if seen[tid]
          seen[tid] = true
          topic_ids_ordered << tid
        end

        topic_ids_csv   = topic_ids_ordered.join(",")
        topic_ids_count = topic_ids_ordered.length
        first_topic_id  = topic_ids_ordered[0] ? topic_ids_ordered[0].to_s : ""

        form_kv = [
          [::DigestReport::EMAIL_ID_FIELD, email_id],
          [::DigestReport::OPEN_TRACKING_USED_FIELD, open_tracking_used],
          ["user_email", user_email],

          [::DigestReport::FROM_EMAIL_FIELD, from_email],

          [::DigestReport::USER_ID_FIELD, user_id],
          [::DigestReport::USERNAME_FIELD, username],
          [::DigestReport::USER_CREATED_AT_FIELD, user_created_at_utc],

          [::DigestReport::SUBJECT_FIELD, subject],
          [::DigestReport::SUBJECT_PRESENT_FLD, subject_present],

          [::DigestReport::TOPIC_IDS_FIELD, topic_ids_csv],
          [::DigestReport::TOPIC_COUNT_FIELD, topic_ids_count.to_s],
          [::DigestReport::FIRST_TOPIC_ID_FIELD, first_topic_id]
        ]

        body = URI.encode_www_form(form_kv)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout  = ::DigestReport::OPEN_TIMEOUT_SECONDS
        http.read_timeout  = ::DigestReport::READ_TIMEOUT_SECONDS
        http.write_timeout = ::DigestReport::WRITE_TIMEOUT_SECONDS if http.respond_to?(:write_timeout=)

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req["User-Agent"]   = "Discourse/#{Discourse::VERSION::STRING} #{::DigestReport::PLUGIN_NAME}"
        req.body = body

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

        begin
          res = http.start { |h| h.request(req) }
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

          code = res.code.to_i
          if code >= 200 && code < 300
            ::DigestReport.log("POST OK code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} first_topic_id=#{first_topic_id}")
          else
            ::DigestReport.log_error("POST FAIL code=#{res.code} ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} body=#{res.body.to_s[0, 500].inspect}")
          end
        rescue StandardError => e
          ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
          ::DigestReport.log_error("POST ERROR ms=#{ms} email_id=#{email_id} open_tracking_used=#{open_tracking_used} topic_ids_count=#{topic_ids_count} err=#{e.class}: #{e.message}")
        ensure
          begin
            http.finish if http.started?
          rescue StandardError
          end
        end
      rescue StandardError => e
        ::DigestReport.log_error("JOB CRASH err=#{e.class}: #{e.message}")
      end
    end
  end

  # 4) After send: enqueue postback; prefer header email_id; if missing, STRICT rescan (must have u= and email_id=20digits)
  DiscourseEvent.on(:after_email_send) do |message, email_type|
    begin
      next unless ::DigestReport.enabled?
      next unless email_type.to_s == "digest"

      recipient = ::DigestReport.first_recipient_email(message)

      subject =
        begin
          ::DigestReport.safe_str(message&.subject, ::DigestReport::SUBJECT_MAX_LEN)
        rescue StandardError
          ""
        end

      from_email =
        begin
          Array(message&.from).first.to_s.strip
        rescue StandardError
          ""
        end

      email_id = ::DigestReport.header_val(message, "X-Digest-Report-Email-Id")
      open_tracking_used = ::DigestReport.header_val(message, "X-Digest-Report-Open-Tracking-Used")
      open_tracking_used = (open_tracking_used == "1" ? "1" : "0")

      user_id_hdr = ::DigestReport.header_val(message, "X-Digest-Report-User-Id")

      if email_id.empty? || !email_id.match?(/\A\d{20}\z/)
        tracking = ::DigestReport.extract_tracking_from_message(message)
        email_id = tracking[:email_id].to_s.strip if email_id.empty?
        user_id_hdr = tracking[:user_id].to_s.strip if user_id_hdr.empty?
      end

      if email_id.empty? || !email_id.match?(/\A\d{20}\z/)
        ::DigestReport.log_error("STRICT RESCAN FAILED after send: no email_id=20digits found; using random fallback")
        email_id = ::DigestReport.random_20_digit_id
      end

      user = nil
      begin
        user = User.find_by_email(recipient) unless recipient.empty?
      rescue StandardError
        user = nil
      end

      user_id  = user_id_hdr.empty? ? (user ? user.id.to_s : "") : user_id_hdr
      username = user ? user.username.to_s : ""
      user_created_at_utc = user ? ::DigestReport.safe_iso8601(user.created_at) : ""

      topic_ids = ::DigestReport.extract_topic_ids_from_message(message)
      first_topic_id = topic_ids[0] ? topic_ids[0].to_s : ""

      Jobs.enqueue(
        :digest_report_postback,
        email_id: email_id,
        open_tracking_used: open_tracking_used,
        user_email: recipient,
        from_email: from_email,
        user_id: user_id,
        username: username,
        user_created_at_utc: user_created_at_utc,
        subject: subject,
        topic_ids: topic_ids
      )

      ::DigestReport.log("Enqueued postback email_id=#{email_id} open_tracking_used=#{open_tracking_used} user_id=#{user_id} topic_ids_count=#{topic_ids.length} first_topic_id=#{first_topic_id}")
    rescue StandardError => e
      ::DigestReport.log_error("ENQUEUE ERROR err=#{e.class}: #{e.message}")
    end
  end
end
