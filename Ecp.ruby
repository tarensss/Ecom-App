# Gemfile
gem 'rails', '~> 6.1.0'
gem 'pg', '~> 1.2'
gem 'puma', '~> 5.0'
gem 'bcrypt', '~> 3.1.7'
gem 'jwt', '~> 2.2'
gem 'rack-cors', '~> 1.1'
gem 'aws-sdk-s3', '~> 1.112'
gem 'active_model_serializers', '~> 0.10.0'
gem 'jbuilder', '~> 2.10'

group :development, :test do
  gem 'pry-rails', '~> 0.3.9'
  gem 'dotenv-rails', '~> 2.7'
end

group :development do
  gem 'listen', '~> 3.3'
  gem 'spring'
  gem 'spring-watcher-listen', '~> 2.0.0'
end

group :test do
  gem 'factory_bot_rails', '~> 6.2'
  gem 'faker', '~> 2.11'
  gem 'rspec-rails', '~> 5.0'
  gem 'shoulda-matchers', '~> 4.5'
  gem 'database_cleaner-active_record', '~> 2.0'
end

# config/application.rb
config.api_only = true

# config/initializers/cors.rb
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'
    resource '*', headers: :any, methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end

# app/controllers/authentication_controller.rb
class AuthenticationController < ApplicationController
  skip_before_action :authorize_request, only: :authenticate

  def authenticate
    auth_token =
      AuthenticateUser.new(
        params[:email],
        params[:password]
      ).call
    json_response(auth_token: auth_token)
  end
end

# app/controllers/concerns/response.rb
module Response
  def json_response(object, status = :ok)
    render json: object, status: status
  end

  def json_error(error, status = :unprocessable_entity)
    render json: { error: error }, status: status
  end
end

# app/controllers/concerns/exception_handler.rb
module ExceptionHandler
  extend ActiveSupport::Concern

  included do
    rescue_from ActiveRecord::RecordNotFound do |e|
      json_error(e.message, :not_found)
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      json_error(e.message, :unprocessable_entity)
    end

    rescue_from JWT::DecodeError do |e|
      json_error(e.message, :unauthorized)
    end

    rescue_from JWT::ExpiredSignature do |e|
      json_error(e.message, :unauthorized)
    end
  end
end

# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  include Response
  include ExceptionHandler

  before_action :authorize_request
  attr_reader :current_user

  private

  def authorize_request
    @current_user = AuthorizeApiRequest.new(request.headers).call
  end
end

# app/controllers/posts_controller.rb
class PostsController < ApplicationController
  before_action :set_post, only: [:show, :update, :destroy]

  def index
    @posts = Post.all
