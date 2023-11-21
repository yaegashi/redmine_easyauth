class EasyauthController < AccountController
  def easyauth_failure
    flash['error'] = "#{l('easyauth.error.authentication_failed')}: #{params[:message]}"
    redirect_to signin_path
  end

  def easyauth_login
    unless settings['enabled']
      flash['error'] = l('easyauth.error.disabled')
      redirect_to signin_path
      return
    end

    # Extract user principal information from request headers
    # https://learn.microsoft.com/en-us/azure/app-service/configure-authentication-user-identities
    # X-MS-CLIENT-PRINCIPAL: Base64 encoded JSON object
    # X-MS-CLIENT-PRINCIPAL-NAME: User's mail address

    name = request.headers['HTTP_X_MS_CLIENT_PRINCIPAL_NAME']
    logger.info "easyauth name: #{name.inspect}"

    principal_raw = request.headers['HTTP_X_MS_CLIENT_PRINCIPAL']
    logger.info "easyauth principal raw: #{principal_raw.inspect}"

    begin
      principal = JSON.parse(Base64.decode64(principal_raw))
      raise 'not a hash' unless principal.is_a?(Hash)
    rescue => e
      logger.error "easyauth principal decode error: #{e}"
      principal = {}
    end
    logger.info "easyauth principal decoded: #{principal.inspect}"

    if name.blank?
      logger.info 'easyauth unavailable'
      flash['error'] = l('easyauth.error.authentication_unavailable')
      redirect_to signin_path
      return
    end

    claims = {}
    if principal['auth_typ'] == 'aad'
      principal.fetch('claims', []).each do |claim|
        k = claim['typ'].to_s
        v = claim['val'].to_s
        next if k.blank? || v.blank?
        claims[k] = claims.fetch(k, []) + [v]
      end
    end

    claim_groups = (claims.fetch('groups', []) + [claimis['oid']]).map(&:strip).map(&:downcase).reject(&:blank?).uniq
    logger.info "easyauth claim groups: #{claim_groups.inspect}"

    allowed_groups = settings['allowed_principal_list'].to_s.split(',').map(&:strip).map(&:downcase).reject(&:blank?).uniq
    logger.info "easyauth allowed groups: #{allowed_groups.inspect}"

    if allowed_groups.any? && (allowed_groups & claim_groups).empty?
      logger.info 'easyauth disallowed'
      flash['error'] = l('easyauth.error.authentication_disallowed')
      redirect_to signin_path
      return
    end

    user = User.joins(:email_addresses)
               .where('email_addresses.address' => name, 'email_addresses.is_default' => true)
               .first_or_initialize

    if user.new_record?
      unless settings['auto_registration']
        logger.info 'easyauth auto registration disabled'
        flash['error'] = l('easyauth.error.authentication_disabled')
        redirect_to signin_path
        return
      end
      logger.info 'easyauth auto registration not implemented'
      flash['error'] = l('easyauth.error.auto_registration_failed')
      redirect_to signin_path
      return
    end

    if user.active?
      successful_authentication(user)
      return
    end
    account_pending
  end

  def settings
    @settings ||= Setting.plugin_redmine_easyauth
  end
end
