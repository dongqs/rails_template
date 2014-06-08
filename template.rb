gsub_file "Gemfile", "https://rubygems.org", "https://ruby.taobao.org"

gem "slim-rails"
gem "therubyracer"
gem "figaro"
gem "bootstrap-sass"
gem "simple_form", "~> 3.1.0.rc1"
gem "quiet_assets"
gem "kaminari"
gem "rest-client"
gem "puma"
gem "mysql2"
gem "devise"
gem "devise_ldap_authenticatable"

gem_group :development, :test do
  gem "better_errors"
  gem "binding_of_caller"
end


# run "bundle install --local" # for development
run "bundle install"


# .gitignore
append_file ".gitignore", <<-EOF
  /config/application.yml
  /config/database.yml
  /config/secrets.yml
  /config/ldap.yml
  /config/sidekiq.yml
  *.swp
  /coverage
  .DS_Store
EOF


# database config example
run "cp config/database.yml config/database.yml.example"


# figaro
generate "figaro:install"
run "cp config/application.yml config/application.yml.example"


# slim
run "rm app/views/layouts/application.html.erb"
create_file "app/views/layouts/application.html.slim", <<-EOF
doctype html
html
  head
    title Template
    = stylesheet_link_tag 'application', media: 'all', 'data-turbolinks-track' => true
    = javascript_include_tag 'application', 'data-turbolinks-track' => true
    = csrf_meta_tags
    style
      |  body { padding-top: 50px; } .starter-template { padding: 40px 15px; text-align: center; }
  body
    .navbar.navbar-inverse.navbar-fixed-top[role="navigation"]
      .container
        .navbar-header
          button.navbar-toggle[type="button" data-toggle="collapse" data-target=".navbar-collapse"]
            span.sr-only
              | Toggle navigation
            span.icon-bar
            span.icon-bar
            span.icon-bar
          a.navbar-brand[href="#"]
            | Project name
        .collapse.navbar-collapse
          ul.nav.navbar-nav
            li = link_to 'Home', root_path
            - if user_signed_in?
              li = link_to "Sign out", destroy_user_session_path, method: :delete
            - else
              li = link_to "Sign in", new_user_session_path
    .container
      #flash
        - flash.each do |key, value|
          = content_tag(:div, value, class: "alert alert-\#{key}")
      == yield
EOF


# bootstrap
create_file "app/assets/stylesheets/custom.css.scss", '@import "bootstrap";'
inject_into_file "app/assets/javascripts/application.js", "//= require bootstrap\n", after: "//= require turbolinks\n"


# simple_form
generate "simple_form:install --bootstrap"
remove_file "lib/templates/slim/scaffold/_form.html.slim"
create_file "lib/templates/slim/scaffold/_form.html.slim", <<-EOF
= simple_form_for(@<%= singular_table_name %>, html: { class: 'form-horizontal' }, wrapper: :horizontal_form, wrapper_mappings: { check_boxes: :horizontal_radio_and_checkboxes, radio_buttons: :horizontal_radio_and_checkboxes, file: :horizontal_file_input, boolean: :horizontal_boolean }) do |f|
  = f.error_notification

  .form-inputs
<%- attributes.each do |attribute| -%>
    = f.<%= attribute.reference? ? :association : :input %> :<%= attribute.name %>
<%- end -%>

  .form-actions
    = f.button :submit
EOF


# static pages
generate "controller", "static_pages", "home", "status"
inject_into_file "app/controllers/static_pages_controller.rb", after: "def status\n" do
<<-EOF
    render json: {
      status: "ok",
      hostname: Socket.gethostname,
      service: "mushroom",
      commit: @@comment ||= `git log -1 --oneline`
    }
EOF
end

gsub_file "config/routes.rb", "get 'static_pages/home'", "root to: 'static_pages#home'"
gsub_file "config/routes.rb", "get 'static_pages/status'", "get '/status' => 'static_pages#status'"


# devise"
generate "devise:install"
generate "devise:views"
generate "devise", "user"
rake "db:migrate"


# devise_ldap_authenticatable"
generate "devise_ldap_authenticatable:install"
run "cp config/ldap.yml config/ldap.yml.bak"

generate "migration", "add_username_to_users", "username:string:index"
rake "db:migrate"

gsub_file "app/models/user.rb", "devise :ldap_authenticatable, :registerable,", ""
gsub_file "app/models/user.rb", ":recoverable, :rememberable, :trackable, :validatable", <<-EOF

  unless Rails.env.production?
    devise :database_authenticatable, :rememberable, :trackable, :registerable# , :recoverable, :validatable
  else
    devise :ldap_authenticatable, :rememberable, :trackable, :registerable# , :recoverable, :validatable

    before_validation :get_ldap_email, :get_ldap_id

    def get_ldap_email
      self.email = Devise::LDAP::Adapter.get_ldap_param(self.username,"mail").first
    end

    def get_ldap_id
      self.id = Devise::LDAP::Adapter.get_ldap_param(self.username,"uidnumber").first
    end

    # hack for remember_token
    def authenticatable_salt
      Digest::SHA1.hexdigest(email)[0,29]
    end
  end

  def name
    self.username
  end
EOF
gsub_file "app/views/devise/sessions/new.html.erb", "email", "username"
gsub_file "config/initializers/devise.rb", "# config.ldap_logger = true", "config.ldap_logger = true"
gsub_file "config/initializers/devise.rb", "# config.ldap_create_user = false", "config.ldap_create_user = true"
gsub_file "config/initializers/devise.rb", "# config.ldap_update_password = true", "config.ldap_update_password = true"
gsub_file "config/initializers/devise.rb", "# config.ldap_use_admin_to_bind = false", "config.ldap_use_admin_to_bind = true"
gsub_file "config/initializers/devise.rb", "# config.authentication_keys = [ :email ]", "config.authentication_keys = [ :username ]"
gsub_file "config/initializers/devise.rb", "config.password_length = 8..128", "config.password_length = 4..128"


# CMS
generate "scaffold", "blog", "title:string", "content:text", "published_at:datetime", "visits:integer", "public:boolean", "category:string"
rake "db:migrate"
