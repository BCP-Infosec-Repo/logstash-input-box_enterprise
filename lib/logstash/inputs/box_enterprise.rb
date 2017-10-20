# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "rufus/scheduler"
require "socket" # for Socket.gethostname
require "logstash/plugin_mixins/http_client"
require "manticore"
require "openssl"
require "jwt"
require "json"
require "cgi"

MAX_FILE_SIZE = 10 * 2**20


class LogStash::Inputs::BoxEnterprise < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient
  
  config_name "box_enterprise"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "json"

  # Set how many messages you want to pull with each request
  #
  # The default, `100`, means to fetch 100 events at a time.
  # The maximum value is 500.
  config :chunk_size, :validate => :number, :default => 100

  # Schedule of when to periodically poll from the urls
  # Format: A hash with
  #   + key: "cron" | "every" | "in" | "at"
  #   + value: string
  # Examples:
  #   a) { "every" => "1h" }
  #   b) { "cron" => "* * * * * UTC" }
  # See: rufus/scheduler for details about different schedule options and value string format
  config :schedule, :validate => :hash, :required => true

  # The Oauth2 Client ID used to access the Box.com API
  #
  # Format: A string wtih the client ID
  config :client_id, :validate => :string, :required => true

  # The Oauth2 Client secret to pull the events
  # Here to allow it via enviornment variable
  #
  # Format: A string with the client secret to send
  config :client_secret_env, :validate => :string

  # The Oauth2 Client secret to pull events, stored in a file
  #
  # Format: A valid path containing the client_secret
  config :client_secret_file, :validate => :path

  # The Box.com Enterprise ID associated with the customer.
  # Used in the JWT
  #
  # Format: String
  config :enterprise_id, :validate => :string, :required => true

  # The kid for the jwt that corresponds to the uploaded key.
  # The corresponding private key must be accessible by this file.
  # 
  # Format: String
  config :kid, :validate => :string, :required => true

  # The algorithim that the private/public key pair used
  # Supported values: RS256, RS384, or RS512
  #
  # Format: String containing one of the above values
  config :algo, :validate => :string, :default => "RS256"

  # The file where the private key is stored.
  #
  # Format: Filepath
  config :private_key_file, :validate => :path, :required => true

  # The private key password stored in an envionrment.
  # WARNING: Avoid storing the private key password directly in this file.
  # This method is provided solely to add the key password via environment variable.
  # This will contain the password for the private key for the Box.com instance.
  #
  # Format: File path
  config :private_key_pass_env, :validate => :string

  # The file in which the password for private key 
  # WARNING: This file should be VERY carefully monitored.
  # This will contain the private_key which can have a lot access to your Box.com instance.
  # It cannot be stressed enough how important it is to protect this file.
  #
  # Format: File path
  config :private_key_pass_file, :validate => :path

  # The base filename to store the pointer to the current location in the logs
  # This file will be renamed with each new reference to limit loss of this data
  # The location will need at least write and execute privs for the logstash user
  # This parameter is not required, however on start logstash will ship all logs to your SIEM.
  #
  # Format: Filepath
  # This is not the filepath of the file itself, but rather the base name of the file
  config :state_file_base, :validate => :string

  # The events to filter on using Box.com event filter
  # This an API filter, not local, fetch only events that are needed
  #
  # Format: Comma separated string with the events to filter on
  # Use: https://docs.box.com/reference#section-enterprise-events
  config :event_type, :validate => :string
  
  # The date and time after which to fetch events
  #
  # Format: string with a RFC 3339 formatted date (e.g. 2016-10-09T22:25:06-07:00)
  config :created_after, :validate => :string

  # The date and time before which to fetch events
  #
  # Format: string with a RFC 3339 formatted date (e.g. 2016-10-09T22:25:06-07:00)
  config :created_before, :validate => :string

  # Define the target field for placing the received data.
  # If this setting is omitted, the data will be stored at the root (top level) of the event.
  #
  # Format: String
  config :target, :validate => :string

  # If you'd like to work with the request/response metadata.
  # Set this value to the name of the field you'd like to store a nested
  # hash of metadata.
  #
  # Format: String
  config :metadata_target, :validate => :string, :default => '@metadata'

  public
  Schedule_types = %w(cron every at in)
  def register

    algo_types = %w(RS256 RS384 RS512)
    msg_invalid_algo = "Invalid config. Algo string must contain " +
      "exactly one of the following strings - RS256, RS384, or RS512"
    raise LogStash::ConfigurationError, msg_invalid_algo unless algo_types.include?(@algo)

    unless (@chunk_size > 0 and @chunk_size <= 500)
      raise LogStash::ConfigurationError, "Chunk size must be between 1 and 500"
    end

    if (@created_after)
      begin
        @created_after = DateTime.parse(@created_after).rfc3339()
      rescue ArgumentError => e
        raise LogStash::ConfigurationError, "created_after must be of the form " +
          "yyyy-MM-dd’‘T’‘HH:mm:ssZZ, e.g. 2013-01-01T12:00:00-07:00."
      end
      @created_after = CGI.escape(@created_after)
    end

    if (@created_before)
      begin
        @created_before = DateTime.parse(@created_before).rfc3339()
      rescue ArgumentError => e
        raise LogStash::ConfigurationError, "created_before must be of the form " +
          "yyyy-MM-dd’‘T’‘HH:mm:ssZZ, e.g. 2013-01-01T12:00:00-07:00."
      end
      @created_before = CGI.escape(@created_before)
    end

    @event_type = CGI.escape(@event_type) if @event_type

    if (@private_key_pass_env and @private_key_pass_file)
      raise LogStash::ConfigurationError, "Both private_key_file and private_key_env cannot be set. Please select one for use."
    end
    unless (@private_key_pass_env or @private_key_pass_file)
      raise LogStash::ConfigurationError, "Both private_key_file and private_key_env cannot be empty. Please select one for use."
    end

    if (@private_key_pass_file)
      begin
        if (File.size(@private_key_pass_file) > MAX_FILE_SIZE)
          raise LogStash::ConfigurationError, "The private key password file is too large to map"
        else
          @private_key_pass = File.read(@private_key_pass_file).chomp
          @logger.info("Successfully opened private_key_pass_file",:private_key_pass_file => @private_key_pass_file)
        end
      rescue LogStash::ConfigurationError
        raise
      # Some clean up magic to cover the stuff below.
      # This will keep me from stomping on signal interrupts and ctrl+c
      rescue SignalException, Interrupt, SyntaxError
        raise
      rescue Exception => e
        # This is currently a bug in logstash, confirmed here:
        # https://discuss.elastic.co/t/logstash-configurationerror-but-configurationok-logstash-2-4-0/65727/2
        # Will need to determine the best way to handle this
        # Rather than testing all error conditions, this can just display them.
        # Should figure out a way to display this in a better fashion.
        raise LogStash::ConfigurationError, e.inspect
      end
    else
      @private_key_pass = @private_key_pass_env
    end

    if (@client_secret_env and @client_secret_file)
      raise LogStash::ConfigurationError, "Both client_secret_file and client_secret_env cannot be set. Please select one for use."
    end
    unless (@client_secret_env or @client_secret_file)
      raise LogStash::ConfigurationError, "Both client_secret_file and client_secret_env cannot be empty. Please select one for use."
    end

    if (@client_secret_file)
      begin
        if (File.size(@client_secret_file) > MAX_FILE_SIZE)
          raise LogStash::ConfigurationError, "The client secret file is too large to map"
        else
          @client_secret = File.read(@client_secret_file).chomp
          @logger.info("Successfully opened client_secret_file",:client_secret_file => @client_secret_file)
        end
      rescue LogStash::ConfigurationError
        raise
      # Some clean up magic to cover the stuff below.
      # This will keep me from stomping on signal interrupts and ctrl+c
      rescue SignalException, Interrupt, SyntaxError
        raise
      rescue Exception => e
        # This is currently a bug in logstash, confirmed here:
        # https://discuss.elastic.co/t/logstash-configurationerror-but-configurationok-logstash-2-4-0/65727/2
        # Will need to determine the best way to handle this
        # Rather than testing all error conditions, this can just display them.
        # Should figure out a way to display this in a better fashion.
        raise LogStash::ConfigurationError, e.inspect
      end
    else
      @client_secret = @client_secret_env
    end

    if (File.size(@private_key_file) < MAX_FILE_SIZE)
      begin
       @private_key = OpenSSL::PKey::RSA.new(File.read(@private_key_file),@private_key_pass)
      rescue SignalException, Interrupt, SyntaxError
        raise
       # This is currently a bug in logstash, confirmed here:
       # https://discuss.elastic.co/t/logstash-configurationerror-but-configurationok-logstash-2-4-0/65727/2
       # Will need to determine the best way to handle this
       # Rather than testing all error conditions, this can just display them.
       # Should figure out a way to display this in a better fashion.
       rescue Exception => e
        raise LogStash::ConfigurationError, e.inspect
      end
    else
      raise LogStash::ConfigurationError, "The private key file appears to be too big to be mapped."
    end



    if (@state_file_base)
      dir_name = File.dirname(@state_file_base)
      ## Generally the state file directory will have the correct permissions
      ## so check for that case first.
      if (File.readable?(dir_name) and File.executable?(dir_name) and
        File.writable?(dir_name))
        @state_file = Dir[@state_file_base + "*"].sort.last
      else
	      ## Build one message for the rest of the issues
	      access_message = "Could not access the state file dir" + 
	        "#{dir_name} for the following reasons: "
	      unless (File.readable?(dir_name))
	        access_message << "Cannot read #{dir_name}."
	      end
	      unless (File.executable?(dir_name))
	        access_message << "Cannot list directory or perform special" +
	        "operations on #{dir_name}."
	      end
	      unless (File.writable?(dir_name))
	        access_message << "Cannot write to #{dir_name}."
	      end
	      access_message << "Please provide the appopriate permissions."
        raise LogStash::ConfigurationError, access_message
      end
 
      # There is a state file so get the state data from it.
      if (@state_file)
        @next_stream_position = @state_file.slice(/(?<state_file>#{@state_file_base})(?<state>[0-9]+)/,'state')
      # If not create the state file
      else
        begin
          @state_file = @state_file_base + "start"
          @logger.info("Created base state_file", :state_file => @state_file)
	        # 'touch' a file to keep the conditional from happening later
          File.open(@state_file, "w") {}
        # Some clean up magic to cover the stuff below.
        # This will keep me from stomping on signal interrupts and ctrl+c
        rescue SignalException, Interrupt, SyntaxError
          raise
        rescue Exception => e
          raise LogStash::ConfigurationError, "Could not create #{@statefile}. " +
            "Error: #{e.inspect}."
        end
      end
    end


    # The auth URL from box that leverages oauth
    @auth_url = "https://api.box.com/oauth2/token"
    @event_url = "https://api.box.com/2.0/events"
    @host = Socket.gethostname

    # Generate a random alpha-numeric string that is 128 chars long
    jti = (0...128).map { (('a'..'z').to_a + ('A'..'Z').to_a)[rand(52)] }.join
    @payload = { :iss => @client_id,				# The Client ID of the service that created the JWT assertion.
                 :sub => @enterprise_id,			# enterprise_id for a token specific to an enterprise when creating and managing app users.
                 :box_sub_type => 'enterprise', 		# “enterprise” or “user” depending on the type of token being requested in the sub claim.
                 :aud => @auth_url,			 	# Always “https://api.box.com/oauth2/token” for OAuth2 token requests
                 :jti => jti, 					# A unique identifier specified by the client for this JWT. This is a unique string that is at least 16 characters and at most 128 characters.
                 :exp => 0 }					# The unix time as to when this JWT will expire. 
								## This can be set to a maximum value of 60 seconds beyond the issue time. Note: It is recommended to set this value to less than the maximum allowed 60 seconds.
								## Note: It is recommended to set this value to less than the maximum allowed 60 seconds.

    @header = {	:kid => @kid,		# Public Key ID generated by Box and provided upon submission of a Public Key. Identifies which Public Key a client is using.
		:alg => @algo, 		# The algorithm used to verify the signature. Values may only be set to: “RS256″, “RS384″, or “RS512.
		:typ => "JWT" }		# Type of token. Default is “JWT” to specify a JSON Web Token (JWT).

    @logger.debug("JWT created", :jsot => @payload)

  end # def register

  def run(queue)
    
    auth_token = "" ## Empty string to treat as a reference to pass around functions
    msg_invalid_schedule = "Invalid config. schedule hash must contain " +
      "exactly one of the following keys - cron, at, every or in"

    raise LogStash::ConfigurationError, msg_invalid_schedule if @schedule.keys.length !=1
    schedule_type = @schedule.keys.first
    schedule_value = @schedule[schedule_type]
    raise LogStash::ConfigurationError, msg_invalid_schedule unless Schedule_types.include?(schedule_type)

    @scheduler = Rufus::Scheduler.new(:max_work_threads => 1)

    #as of v3.0.9, :first_in => :now doesn't work. Use the following workaround instead
    opts = schedule_type == "every" ? { :first_in => 0.01 } : {} 
    opts[:overlap] = false;

    params_event = {:stream_type => "admin_logs"}
    params_event[:limit] = @chunk_size
    params_event[:created_after] = @created_after if @created_after
    params_event[:created_before] = @created_before if @created_before
    params_event[:event_type] = @event_type if @event_type

    @scheduler.send(schedule_type, schedule_value, opts) { run_once(queue,auth_token,params_event) }

    @scheduler.join

  end # def run
  private
  def run_once(queue,auth_token,params_event)

    run_fetcher(queue,auth_token,params_event)

  end

  def run_fetcher(queue,auth_token,params_event)

    @continue = true

    if auth_token.nil? or auth_token.empty?
      handle_auth(queue, auth_token)
    end

    begin

      #loop_count = 0
      while @continue and !stop?

        if @next_stream_position
          params_event[:stream_position] = @next_stream_position
        end

        @logger.debug("Calling URL",
          :event_url  => @event_url,
          :params => params_event,
          :auth_set =>  auth_token.length > 0)


        started = Time.now
        client.async.get(@event_url, params: params_event, headers: {"Authorization" => "Bearer #{auth_token}"}).
          on_success { |response | handle_success(queue, response, auth_token, @event_url, Time.now - started) }.
          on_failure { |exception | handle_failure(queue, exception, @event_url, Time.now - started) }

        client.execute!

        #puts loop_count
        #loop_count += 1

      end

    # Some clean up magic to cover the stuff below.
    # This will keep me from stomping on signal interrupts and ctrl+c
    rescue SignalException, Interrupt, SyntaxError
      raise

    rescue Exception => e
      @logger.fatal("Could not call URL",
        :url  => @event_url,
        :params => params_event,
        :auth_set => auth_token.length > 0,
        :exception  => e.inspect)
      raise
    ensure
      if (@state_file_base && @state_file != "#{@state_file_base}#{@next_stream_position ||= 'start'}" )
        begin
          #puts "Old state file: #{@state_file}"
          File.rename(@state_file,@state_file_base + @next_stream_position)
        rescue SignalException, Interrupt, SyntaxError
          raise
        rescue Exception => e
          @logger.fatal("Could not rename file",
            :old_file => @state_file,
            :new_file => @state_file_base + @next_stream_position,
            :exception => e.inspect)
          raise
        end
          @state_file = @state_file_base + @next_stream_position
          #puts "New state file: #{@state_file}"
      end
    end


  end

  private
  def handle_auth(queue, auth_token)

    @logger.debug("Authenticating to box.com")
    ## clear out the old auth token if it exists
    auth_token.clear

    @payload[:exp] = Time.now.to_i + 30

    @logger.debug("Created JWT json",
      :json => @payload)
    token = JWT.encode(@payload, @private_key, @algo, @header)

    response = client.post(@auth_url, params: {grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_secret: @client_secret, client_id: @client_id, assertion: token}).
      on_failure { |exception | handle_failure(queue, exception, @auth_url, nil) }

    begin
      if response.body.length > 0 and response.code == 200
        @logger.info("Successfully authenticated to box.com")
        auth_token << JSON.parse(response.body)["access_token"]
	      #puts auth_token ## TODO: Remove testing code
      else
        @continue = false
        handle_unknown_error(queue, response, nil, nil)
      end
    rescue NoMethodError => e
      @continue = false
    end


  end # end handle_auth

  private
  def handle_success(queue, response,auth_token, requested_url, exec_time)

     case response.code
     when 200
      if response.body.length > 0
        response_hash = JSON.parse(response.body)
        #puts "current stream position #{@next_stream_position ||= 'nil'}"
        #puts "Next stream position #{response_hash["next_stream_position"]}"
        begin
          if (@next_stream_position && @next_stream_position == response_hash.fetch("next_stream_position") )
            @continue = false
            response_hash["entries"]  = []
          end

          @next_stream_position = response_hash.fetch("next_stream_position")
          #puts response_hash["chunk_size"]
        rescue KeyError
          @logger.error("Could not parse next_stream_position out of the response",:response_body => response_hash)
          @continue = false
        end

        
      else
        @continue = false
        response_hash = {"entries" => {} }
      end

       #response_hash["entries"].each do |entry|
      @codec.decode(response_hash["entries"].to_json) do |decoded|
        #event = @target ? LogStash::Event.new(@target => entry) : LogStash::Event.new(entry)
        event = @target ? LogStash::Event.new(@target => decoded.to_hash) : decoded
        apply_metadata(event,requested_url, response, exec_time)
        decorate(event)
        queue << event
      end

      when 401

        @logger.warn("Auth failed, calling handle_auth to reauthenticate.")
        handle_auth(queue, auth_token)

      else

        @continue = false
        handle_unknown_error(queue,response,requested_url, exec_time)

      end

  end # end handle_success

  def handle_unknown_error(queue,response, requested_url, exec_time)
    @continue = false

    event_hash = {
      "Box-Plugin-Status" => "Box.com server error",
      "Box-Error-Headers" => response.headers,
      "Box-Error-Code"  => response.code,
      "Box=Error-Msg" =>  JSON.parse(response.body)["message"],
      "Box-Error-Raw-Msg" =>  response.body
      }

    event = @target ? LogStash::Event.new(@target => event_hash) : LogStash::Event.new(event_hash)
    event.tag("_box_response_failure")
    apply_metadata(event,requested_url, response, exec_time)
    decorate(event)
    queue << event

    return nil

  end


  def handle_failure(queue, exception, requested_url, exec_time)
    @continue = false
    @logger.warn("Client connection error",
      :exception => exception.inspect)


    event_message_hash = {
      "Box-Plugin-Status" => "Client Connection error",
      "Connection-Error"  => exception.message,
      "backtrace"         => exception.backtrace
      }

    event_hash = {"http_request_failure" => event_message_hash }

    event = @target ? LogStash::Event.new(@target => event_hash) : LogStash::Event.new(event_hash)
    event.tag("_http_request_failure")
    apply_metadata(event,requested_url, nil, exec_time)
    decorate(event)
    queue << event

    return nil
  end

  private
  def apply_metadata(event, requested_url, response=nil, exec_time=nil)
    return unless @metadata_target

    m = {}

    m = {
      "host" => @host,
      "url" => requested_url,
      "runtime_seconds" => exec_time
      }

    if response
      m["code"] = response.code
      m["response_headers"] = response.headers
      m["response_message"] = response.message
      m["retry_count"] = response.times_retried
    end

    event.set(@metadata_target,m)

  end


  public
  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
    begin
      @scheduler.stop
    rescue NoMethodError => e
      unless (e.message == "undefined method `stop' for nil:NilClass")
        raise
      end
    rescue Exception => e
      @logger.warn("Undefined error", :exception => e.inspect)
      raise
    ensure
      if (@state_file_base && @state_file != "#{@state_file_base}#{@next_stream_position ||= 'start'}" )

        begin
          #puts "Old state file: #{@state_file}"
          File.rename(@state_file,@state_file_base + @next_stream_position)
        rescue SignalException, Interrupt, SyntaxError
          raise
        rescue Exception => e
          @logger.fatal("Could not rename file",
            :old_file => @state_file,
            :new_file => @state_file_base + @next_stream_position,
            :exception => e.inspect)
         raise

        end
        @state_file = @state_file_base + @next_stream_position
        #puts "New state file: #{@state_file}"

      end
    end
  end
end # class LogStash::Inputs::BoxEnterprise
