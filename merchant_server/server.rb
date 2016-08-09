require "active_support/all"
require "sinatra"
require "sinatra/contrib/all"
require "sinatra/cross_origin"
require "braintree"
require "term/ansicolor"
require "base64"

require_relative "./exception_handler"
require_relative "./config_manager"

module MerchantServer
  class Server < Sinatra::Base
    use ExceptionHandling
    register Sinatra::Decompile
    register Sinatra::CrossOrigin
    include Term::ANSIColor

    configure :development do
      #register Sinatra::Reloader
    end

    set :static, true
    set :logging, false

    get "/web" do
      @client_token = Braintree::ClientToken.generate(params)
      erb :index
    end

    get "/" do
      content_type :json

      routes = {}
      routes["DELETE"] = Server.routes["DELETE"].map { |r| Server.decompile(r[0], r[1]) }
      routes["GET"] = Server.routes["GET"].map { |r| Server.decompile(r[0], r[1]) }
      routes["POST"] = Server.routes["POST"].map { |r| Server.decompile(r[0], r[1]) }
      routes["PUT"] = Server.routes["PUT"].map { |r| Server.decompile(r[0], r[1]) }

      JSON.pretty_generate(:message => "Server Up", :config => CONFIG_MANAGER.current, :routes => routes)
    end

    options "/client_token" do
      response.headers["Allow"] = "HEAD,GET,OPTIONS"
      response.headers["Access-Control-Allow-Headers"] = "X-Requested-With, X-HTTP-Method-Override, Content-Type, Cache-Control, Accept"
      200
    end

    after "/client_token" do
      _log_contest_entry("client_token")
    end

    get "/client_token" do
      cross_origin
      begin
        if params["customer_id"]
          Braintree::Customer.create(
            :id => params["customer_id"]
          )
        end

        decode = params.has_key?("decode")
        params.delete("decode")

        status 201
        if decode
          content_type :json
          JSON.pretty_generate(_client_token(:decoded => true))
        elsif request.accept?('application/json')
          content_type :json
          JSON.pretty_generate(:client_token => _client_token)
        else
          content_type :text
          _client_token
        end
      rescue Exception => e
        content_type :json
        status 422
        JSON.pretty_generate(:message => e.message)
      end
    end

    after "/customers/:customer_id" do
      _log_contest_entry("customer_create")
    end

    put "/customers/:customer_id" do
      result = Braintree::Customer.create(
        :id => params[:customer_id]
      )

      content_type :json

      if result.success?
        status 201
        JSON.pretty_generate(:message => "Customer #{params[:customer_id]} created")
      else
        status 422
        JSON.pretty_generate(:message => result.message)
      end
    end

    after "/nonce/transaction" do
      _log_contest_entry("transaction_create")
    end

    post "/nonce/transaction" do
      nonce = nonce_from_params

      content_type :json
      if nonce
        JSON.pretty_generate(sale(nonce, params))
      else
        JSON.pretty_generate(
          :message => "Required params: #{server_config[:nonce_param_names].join(", or ")}"
        )
      end
    end

    after "/customers/:customer_id/vault" do
      _log_contest_entry("payment_method_create")
    end

    post "/customers/:customer_id/vault" do
      content_type :json

      nonce = nonce_from_params
      customer_id = params[:customer_id]

      unless customer_id.present?
        status 422
        JSON.pretty_generate(:message => "Required param: customer_id")
        return
      end

      if nonce
        JSON.pretty_generate(vault(nonce, customer_id))
      else
        JSON.pretty_generate(
          :message => "Required params: #{server_config[:nonce_param_names].join(", or ")}"
        )
      end
    end

    get "/config" do
      content_type :json
      JSON.pretty_generate(CONFIG_MANAGER.as_json)
    end

    get "/config/current" do
      content_type :json
      JSON.pretty_generate(CONFIG_MANAGER.current_account.as_json)
    end

    get "/config/validate" do
      JSON.pretty_generate(:message => CONFIG_MANAGER.validate_environment!)
    end

    before "/log/:contest_name" do
      if request.env['HTTP_AUTHORIZATION'] != ENV['LOG_AUTH']
        halt 403
      end
    end

    delete "/log/:contest_name" do
      if File.exists?("./log/#{params[:contest_name]}")
        File.delete("./log/#{params[:contest_name]}")
      end
    end

    get "/log/:contest_name" do
      if File.exists?("./log/#{params[:contest_name]}")
        File.read("./log/#{params[:contest_name]}")
      end
    end

    error do
      content_type :json
      status 400 # or whatever

      e = env['sinatra.error']
      JSON.pretty_generate({:result => 'error', :message => e.message})
    end

    not_found do
      content_type :json
      JSON.pretty_generate({:message => "Not found. GET / to see all routes"})
    end

    def server_config
      {
        :nonce_param_names => ["nonce", "payment_method_nonce", "paymentMethodNonce"]
      }
    end

    def log(message)
      puts "--- [#{CONFIG_MANAGER.current}] #{message}"
    end

    def _log_contest_entry(path)
      message = "#{Time.new.inspect} -- #{request.user_agent} -- #{response.status} -- #{request.env['HTTP_EMAIL']} (#{request.ip})"
      Dir.mkdir("./log") unless File.exists?("./log")
      open("./log/#{path}", 'a') do |f|
        f.puts message
      end
      log message
    end

    def nonce_from_params
      server_config[:nonce_param_names].find do |nonce_param_name|
        if params[nonce_param_name]
          return params[nonce_param_name]
        end
      end
    end

    def sale(nonce, params)
      transaction_params = {
        :amount => params.fetch(:amount, 1),
        :payment_method_nonce => nonce,
      }

      if params[:merchant_account_id].present?
        transaction_params[:merchant_account_id] = params[:merchant_account_id]
      elsif CONFIG_MANAGER.current_merchant_account.present?
        transaction_params[:merchant_account_id] = CONFIG_MANAGER.current_merchant_account
      end

      if params[:three_d_secure_required].present?
        transaction_params[:options] = {
          :three_d_secure => {
            :required => true,
          }
        }
      end

      log("Creating transaction #{transaction_params.inspect}")

      result = Braintree::Transaction.sale(transaction_params)

      if result.success?
        {:message => "created #{result.transaction.id} #{result.transaction.status}"}
      else
        {:message => result.message}
      end

    rescue Exception => e
      {:message => e.message}
    end

    def vault(nonce, customer_id)
      log("Vaulting payment method #{nonce} for customer #{customer_id}")

      result = Braintree::PaymentMethod.create({
        :customer_id => customer_id,
        :payment_method_nonce => nonce
      })

      if result.success?
        {:message => "Vaulted payment method #{result.payment_method.token}"}
      else
        {:message => result.message}
      end
    end

    def _client_token(options = {})
      client_token = Braintree::ClientToken.generate(params)

      if options[:decoded]
        JSON.parse(Base64.decode64(client_token))
      else
        client_token
      end
    end

    def _color_status(status)
      if status >= 400
        yellow status.to_s
      elsif status >= 500
        red status.to_s
      else
        green status.to_s
      end
    end
  end
end
