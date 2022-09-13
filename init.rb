require 'redmine'

RedmineEasyauthViewListener

Redmine::Plugin.register :redmine_azure_easyauth do
  name 'Redmine Azure EasyAuth plugin'
  author 'YAEGASHI Takeshi'
  description 'Authentication/registration plugin with Azure App Service EasyAuth'
  version '0.0.1'
  author_url 'https://github.com/yaegashi'

  settings default: {
    enabled: false,
    auto_registration: false,
    announcement: ''
  }, partial: 'settings/easyauth_settings'
end
