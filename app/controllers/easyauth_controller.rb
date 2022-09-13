class EasyauthController < AccountController
  def easyauth_failure
    flash['error'] = "#{l('easyauth.error.authentication_failure')}: #{params[:message]}"
    redirect_to signin_path
  end

  def easyauth_login
    unless settings['enabled']
      flash['error'] = l('easyauth.error.disabled')
      redirect_to signin_path
      return
    end

    request.headers.sort.each do |k,v|
      logger.info "#{k}: #{v}"
    end

    name = request.headers['HTTP_X_MS_CLIENT_PRINCIPAL_NAME']
    if name.blank?
      flash['error'] = l('easyauth.error.authentication_unavailable')
      redirect_to signin_path
      return
    end

    user = User.joins(:email_addresses)
               .where('email_addresses.address' => name, 'email_addresses.is_default' => true)
               .first_or_initialize

    if user.new_record?
      unless settings['auto_registration']
        flash['error'] = l('easyauth.error.authentication_failure')
        redirect_to signin_path
        return
      end
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
    @settings ||= Setting.plugin_redmine_azure_easyauth
  end
end
