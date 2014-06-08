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
  gem "spring-commands-rspec"
  gem "rspec-rails"
  gem "guard-rspec"

  gem "shoulda"
  gem "database_cleaner"
  gem "factory_girl_rails"

  gem "better_errors"
  gem "binding_of_caller"
  gem "rack-mini-profiler"
end

gem_group :test do
  gem "simplecov", require: false
  gem "test_after_commit"
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


# application.rb
gsub_file "config/application.rb", "# config.time_zone = 'Central Time (US & Canada)'", "config.time_zone = 'Beijing'"
inject_into_file "config/application.rb", after: "# config.i18n.default_locale = :de\n" do
<<-EOS
    config.generators do |g|
      g.stylesheets false
      g.javascripts false
      g.helper false
      g.test_framework :rspec, view_specs: false, request_specs: false
    end
EOS
end


# database config example
run "cp config/database.yml config/database.yml.example"


# figaro
generate "figaro:install"
run "cp config/application.yml config/application.yml.example"


# slim
remove_file "app/views/layouts/application.html.erb"
create_file "app/views/layouts/application.html.slim", <<-EOF
doctype html
html
  head
    title #{app_path}
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


# rspect
generate "rspec:install"
gsub_file ".rspec", "--warnings\n", ""


# guard
run "guard init rspec"
inject_into_file "Guardfile", ", cmd: 'spring rspec'", after: ":rspec"


# devise
generate "devise:install"
generate "devise:views"
generate "devise", "user"
rake "db:migrate"
prepend_file "spec/rails_helper.rb", <<-EOF
require 'simplecov'
SimpleCov.start
EOF
inject_into_file "spec/rails_helper.rb", after: "RSpec.configure do |config|\n" do
<<-EOF
  config.before(:suite) do
    DatabaseCleaner.strategy = :transaction
    DatabaseCleaner.clean_with(:truncation)
  end

  config.around(:each) do |example|
    DatabaseCleaner.cleaning do
      example.run
    end
  end
EOF
end

create_file "spec/support/devise.rb", <<-EOF
module ValidUserControllerHelper
  def sign_in_user role = :user
    @user ||= FactoryGirl.create role
    sign_in :user, @user
    @user
  end
end

RSpec.configure do |config|
  config.include Devise::TestHelpers, :type => :controller
  config.include Devise::TestHelpers, :type => :view
  config.include ValidUserControllerHelper, :type => :controller
  config.include ValidUserControllerHelper, :type => :view
end

# This support package contains modules for authenticaiting
# devise users for request specs.

# This module authenticates users for request specs.#
module ValidUserRequestHelper
    # Define a method which signs in as a valid user.
    def sign_in_user role = :user
        # ASk factory girl to generate a valid user for us.
        @user ||= FactoryGirl.create role

        # We action the login request using the parameters before we begin.
        # The login requests will match these to the user we just created in the factory, and authenticate us.
        post_via_redirect user_session_path, 'user[username]' => @user.username, 'user[password]' => @user.password
    end
end

# Configure these to modules as helpers in the appropriate tests.
RSpec.configure do |config|
    # Include the help for the request specs.
    config.include ValidUserRequestHelper, :type => :request
end
EOF
inject_into_file "spec/factories/users.rb", after: "factory :user do\n" do
<<-EOF
    sequence(:username) { |n| "test\#{n}" }
    sequence(:email) { |n| "test\#{n}@exampl.com" }
    password "password"
    password_confirmation "password"
EOF
end


# devise_ldap_authenticatable"
generate "devise_ldap_authenticatable:install"
run "cp config/ldap.yml config/ldap.yml.bak"

generate "migration", "add_username_to_users", "username:string:index"
rake "db:migrate"

remove_file "app/models/user.rb"
create_file "app/models/user.rb", <<-EOF
class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable

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

  validates :username, presence:true, uniqueness: true

  def name
    self.username
  end
end
EOF

gsub_file "app/views/devise/sessions/new.html.erb", "email", "username"

inject_into_file "app/views/devise/registrations/new.html.erb", after: "<%= f.input :email, required: true, autofocus: true %>\n" do
<<-EOF
    <%= f.input :username, required: true %>
EOF
end

inject_into_file "app/views/devise/registrations/edit.html.erb", after: "<%= f.input :email, required: true, autofocus: true %>\n" do
<<-EOF
    <%= f.input :username, required: true %>
EOF
end

inject_into_file "config/initializers/devise.rb", after: "# ==> LDAP Configuration~\n" do
<<-EOF
  config.ldap_logger = true"
  config.ldap_create_user = true"
  config.ldap_update_password = true"
  config.ldap_use_admin_to_bind = true"
EOF
end
gsub_file "config/initializers/devise.rb", "# config.authentication_keys = [ :email ]", "config.authentication_keys = [ :username ]"
gsub_file "config/initializers/devise.rb", "config.password_length = 8..128", "config.password_length = 4..128"

inject_into_file "app/controllers/application_controller.rb", after: "protect_from_forgery with: :exception\n" do
<<-EOF
  skip_before_action :verify_authenticity_token, if: :skip_authenticity?
  before_action :authenticate_user!
  before_action :configure_permitted_parameters, if: :devise_controller?

  protected

  def configure_permitted_parameters
    devise_parameter_sanitizer.for(:sign_up) << :email
  end

  def skip_authenticity?
    request.format.json? or params[:skip_authenticity]
  end
EOF
end


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
inject_into_file "spec/controllers/static_pages_controller_spec.rb", after: "RSpec.describe StaticPagesController, :type => :controller do\n" do
<<-EOF

  before { sign_in_user }
EOF
end


# # Blogs for test
# generate "scaffold", "blog", "title:string", "content:text", "published_at:datetime", "visits:integer", "public:boolean", "category:string"
# rake "db:migrate"
# inject_into_file "spec/controllers/blogs_controller_spec.rb", after: "RSpec.describe BlogsController, :type => :controller do\n" do
# <<-EOF
# 
#   before { sign_in_user }
# EOF
# end
