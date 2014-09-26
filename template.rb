git :init
git add: '.'
git commit: "-a -m 'rails new #{app_path}'"

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
gem 'rolify'

gem "sidekiq"
gem "sinatra"

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
run "bundle install -V"


# .gitignore
append_file ".gitignore", <<-EOF
dump.rdb
/config/database.yml
/config/secrets.yml
/config/ldap.yml
/config/sidekiq.yml
*.swp
/coverage
.DS_Store
EOF


# robotes.txt
gsub_file "public/robots.txt", "# User-agent: *", "User-agent: *"
gsub_file "public/robots.txt", "# Disallow: /", "Disallow: /"


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


# production.rb
gsub_file "config/environments/production.rb", "config.serve_static_assets = false", "config.serve_static_assets = true"
gsub_file "config/environments/production.rb", "config.log_level = :info", "config.log_level = :debug"


# database config example
run "cp config/database.yml config/database.yml.example"


# figaro
run "bundle exec figaro install"
run "cp config/application.yml config/application.yml.example"


# sidekiq
append_file "config/application.yml", <<-EOF
REDIS_HOST: localhost
REDIS_PORT: "6379"
EOF
run "cp config/application.yml config/application.yml.example"
create_file "app/workers/hello_worker.rb", <<-EOF
class HelloWorker
  include Sidekiq::Worker
  sidekiq_options queue: :default

  def perform msg
    puts msg
  end
end
EOF
create_file "config/initializers/sidekiq.rb", <<-EOF
Sidekiq.configure_server do |config|
  config.redis = { :url => "redis://\#{ENV['REDIS_HOST']}:\#{ENV['REDIS_PORT']}/0", :namespace => '#{app_path}' }
end

Sidekiq.configure_client do |config|
  config.redis = { :url => "redis://\#{ENV['REDIS_HOST']}:\#{ENV['REDIS_PORT']}/0", :namespace => '#{app_path}' }
end
EOF
create_file "tmp/pids/.keep", ""
create_file "config/sidekiq.yml", <<-EOF
---
:verbose: true
:pidfile: ./tmp/pids/sidekiq.pid
:logfile: ./log/sidekiq.log
:queues:
  - default
development:
  :concurrency: 1
production:
  :concurrency: 2
EOF
inject_into_file "config/routes.rb", after: "Rails.application.routes.draw do\n" do
<<-EOF
  require 'sidekiq/web'
  authenticate :user do
    mount Sidekiq::Web => '/sidekiq'
  end
EOF
end
run "cp config/sidekiq.yml config/sidekiq.yml.example"


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
          a.navbar-brand[href="/"]
            | #{app_path.titleize}
        .collapse.navbar-collapse.pull-right
          ul.nav.navbar-nav
            li = link_to 'Home', root_path
            - if user_signed_in?
              li = link_to "Sign out", destroy_user_session_path, method: :delete
            - else
              li = link_to "Sign in", new_user_session_path
    .container
      #flash
        - flash.each do |key, value|
          div.alert.alert-dismissible role="alert" class="alert-#{key}"
            button.close type="button" data-dismiss="alert"
              span aria-hidden="true"
                | &times;
              span.sr-only Close
            = value
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
run "bundle exec guard init rspec"
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

inject_into_file "spec/rails_helper.rb", after: "# Dir[Rails.root.join(\"spec/support/**/*.rb\")].each { |f| require f }\n" do
<<-EOF
Dir[Rails.root.join("spec/support/**/*.rb")].each { |f| require f } # since rspec 3.1
EOF
end

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

inject_into_file "config/initializers/devise.rb", after: "# ==> LDAP Configuration \n" do
<<-EOF
  config.ldap_logger = true
  config.ldap_create_user = true
  config.ldap_update_password = true
  config.ldap_use_admin_to_bind = true
EOF
end

gsub_file "config/initializers/devise.rb", "# config.authentication_keys = [ :email ]", "config.authentication_keys = [ :username ]"
gsub_file "config/initializers/devise.rb", "config.password_length = 8..128", "config.password_length = 4..128"

inject_into_file "app/controllers/application_controller.rb", after: "protect_from_forgery with: :exception\n" do
<<-EOF
  skip_before_action :verify_authenticity_token, if: :skip_authenticity?
  before_action :authenticate_user!
  before_action :configure_permitted_parameters, if: :devise_controller?
  after_action :log_current_user

  def log_current_user
    logger.info "Current user: \#{current_user.email}" if current_user
  end

  def redirect_back default_path = :root, options = {}
    redirect_to :back, options
  rescue ActionController::RedirectBackError
    redirect_to default_path, options
  end

  def configure_permitted_parameters
    devise_parameter_sanitizer.for(:sign_up) << :email
  end

  def skip_authenticity?
    request.format.json? or params[:skip_authenticity]
  end
EOF
end


# authentication token
generate "migration", "add_authentication_token_to_users", "authentication_token:string:index"
rake "db:migrate"
inject_into_file "app/models/user.rb", after: "class User < ActiveRecord::Base\n" do
<<-EOF
  before_save :ensure_authentication_token

  def ensure_authentication_token
    if authentication_token.blank?
      self.authentication_token = generate_authentication_token
    end
  end

  def generate_authentication_token
    loop do
      token = Devise.friendly_token
      break token unless User.where(authentication_token: token).first
    end
  end
EOF
end
inject_into_file "app/controllers/application_controller.rb", after: "class ApplicationController < ActionController::Base\n" do
<<-EOF
  before_action :authenticate_user_from_token!

  def authenticate_user_from_token!
    auth_token = params[:auth_token].presence
    user       = auth_token && User.find_by_authentication_token(auth_token.to_s)

    if user
      # Notice we are passing store false, so the user is not
      # actually stored in the session and a token is needed
      # for every request. If you want the token to work as a
      # sign in token, you can simply remove store: false.
      sign_in user, store: false
    end
  end
EOF
end
inject_into_file "app/views/devise/registrations/edit.html.erb", after: "<%= f.input :current_password, hint: \"we need your current password to confirm your changes\", required: true %>\n" do
<<-EOF
    <%= f.input :authentication_token, label: "Auth token" do |f| %>
        <input value="<%= resource.authentication_token %>" disabled="disabled"></input>
    <% end %>
EOF
end


# static pages
generate "controller", "static_pages", "home", "status"
inject_into_file "app/controllers/static_pages_controller.rb", after: "class StaticPagesController < ApplicationController\n" do
<<-EOF
  skip_before_action :authenticate_user!, only: [:home, :status]
  skip_before_action :authenticate_normal!, only: [:home, :status]
EOF
end
inject_into_file "app/controllers/static_pages_controller.rb", after: "def status\n" do
<<-EOF
    render json: {
      status: "ok",
      hostname: Socket.gethostname,
      service: "#{app_path}",
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


# rolify
generate "rolify", "Role", "User"
run "cd db/migrate && file=`ls | tail -n 1` && mv $file $file.rb" # hack rolify bug
rake "db:migrate"

inject_into_file "app/models/user.rb", after: "rolify\n" do
<<-EOF
  def managing_roles
    roles = []
    roles += [:system, :admin] if has_role? :system
    roles += [:normal] if has_role? :admin
    roles.uniq
  end
EOF
end
inject_into_file "app/controllers/application_controller.rb", after: "protect_from_forgery with: :exception\n" do
<<-EOF
  before_action :authenticate_normal!

  class AuthenticationError < SecurityError; end
  class AuthorizationError < SecurityError; end

  rescue_from AuthenticationError do |exception|
    flash[:error] = exception.to_s
    redirect_to :root
  end

  rescue_from AuthorizationError do |exception|
    flash[:error] = exception.to_s
    redirect_to :root
  end

  def authenticate_current_user! user
    raise AuthorizationError unless current_user == user or current_user.system?
  end

  def authenticate_role! role, resource = nil
    return unless user_signed_in?
    unless current_user.has_role? role
      raise AuthenticationError, "\#{current_user.name} not authenticated as a \#{role} user"
    end
  end

  def authenticate_any_role! *roles
    return unless user_signed_in?
    unless current_user.has_any_role? *roles
      raise AuthenticationError, "\#{current_user.name} not authenticated as any of \#{roles.join(", ")}"
    end
  end

  Role::USER_ROLES.each do |role|
    define_method "authenticate_\#{role.to_s}!" do
      authenticate_role! role
    end
  end
EOF
end
inject_into_file "app/models/role.rb", after: "scopify\n" do
<<-EOF
  OPERATIONS = [:grant, :revoke]
  USER_ROLES = [:system, :admin, :normal]
EOF
end
gsub_file "spec/support/devise.rb", "role = :user", "role = :system", force: true
inject_into_file "config/routes.rb", after: "Rails.application.routes.draw do\n" do
<<-EOF
  resources :users, only: [:index] do
    member do
      put :role
    end
  end
EOF
end
inject_into_file "spec/factories/users.rb", after: "factory :user do\n" do
<<-EOF
    factory :normal do
      after(:create) do |user|
        user.grant :normal
      end
    end

    factory :admin do
      after(:create) do |user|
        user.grant :normal
        user.grant :admin
      end
    end

    factory :system do
      after(:create) do |user|
        user.grant :normal
        user.grant :system
      end
    end
EOF
end
create_file "app/controllers/users_controller.rb", <<-EOF
class UsersController < ApplicationController

  skip_before_action :authenticate_admin!, only: [:index, :role]

  def index
    authenticate_any_role! :system, :admin
    @users = User.all
    @roles = current_user.managing_roles
  end

  def role
    authenticate_any_role! :system, :admin
    @user = User.find params[:id]
    operation, role = params[:operation].to_sym, params[:role].to_sym

    raise "role operation \#{operation} undefined" unless operation.to_sym.in? Role::OPERATIONS
    raise "user role \#{role} undefined" unless role.to_sym.in? Role::USER_ROLES
    raise "current user not in charge of \#{role}" unless role.to_sym.in? current_user.managing_roles
    @user.send operation, role
    redirect_back :root, notice: "User \#{@user.name} was \#{operation}ed role \#{role}"
  rescue => exc
    redirect_back :root, notice: exc.to_s
  end
end
EOF
create_file "spec/controllers/users_controller_spec.rb", <<-EOF
require 'rails_helper'

RSpec.describe UsersController, :type => :controller do

  let(:valid_session) { { } }

  describe "GET index" do
    it "redirect normal users" do
      @user = sign_in_user :normal
      get :index, {}, valid_session
      expect(response).to redirect_to :root
    end

    it "assigns all users as @users" do
      @user = sign_in_user :admin
      get :index, {}, valid_session
      expect(assigns(:users)).to eq [@user]
      expect(assigns(:roles)).to eq [:normal]
    end

    it "assigns all users as @users" do
      @user = sign_in_user :system
      get :index, {}, valid_session
      expect(assigns(:users)).to eq [@user]
      expect(assigns(:roles)).to eq [:system, :admin]
    end
  end

  describe "PUT role" do

    describe "normal users" do

      it "redirect normal users" do
        sign_in_user :normal
        user = FactoryGirl.create :normal
        operation = :grant
        role = :normal
        put :role, {:id => user.to_param, :operation => operation, :role => role}, valid_session
        expect(response).to redirect_to(:root)
      end
    end

    describe "system users" do

      describe "global roles" do
        it "grant role to user" do
          sign_in_user :system
          user = FactoryGirl.create :system

          expect(user).to_not be_has_role :admin
          put :role, {:id => user.to_param, :operation => :grant, :role => :admin}, valid_session
          expect(assigns(:user)).to be_has_role :admin
        end

        it "revoke role from user" do
          sign_in_user :system
          user = FactoryGirl.create :user
          user.grant 'admin'

          expect(user).to be_has_role :admin
          put :role, {:id => user.to_param, :operation => :revoke, :role => :admin}, valid_session
          expect(assigns(:user)).to_not be_has_role :admin
        end
      end
    end
  end
end
EOF
create_file "app/views/users/index.html.slim", <<-EOF
table.table
  tr
    th Username
    - @roles.each do |role|
      th = role.to_s.titleize
    end
  - @users.each do |user|
    tr
      td = user.username
      - @roles.each do |role|
        td
          = form_for user, url: role_user_path(user), method: :put do |f|
              - operation, activation, btn_class = user.has_role?(role) ? \
                %w(revoke active btn-success) : %w(grant inactive btn-danger)
              = hidden_field_tag :operation, operation
              = hidden_field_tag :role, role
              = f.submit activation, class: "btn \#{btn_class}"
EOF
append_file "db/seeds.rb", <<-EOF
user = User.create! username: "admin", email: "admin@example.com", password: "password", password_confirmation: "password"
Role::USER_ROLES.each do |role|
  user.grant role
end
EOF
rake "db:seed"


# scaffold resources
{
  "book" => [
    "name:string",
    "content:text",
  ]
}.each do |resource, fields|
  generate "scaffold", resource, *fields
  rake "db:migrate"
  inject_into_file "spec/controllers/#{resource.tableize}_controller_spec.rb", after: "RSpec.describe #{resource.pluralize.camelize}Controller, :type => :controller do\n" do
<<-EOF

  before { sign_in_user }
EOF
  end
end

git add: '.'
git commit: "-a -m 'intialized from template'"

run "bundle exec rspec"
