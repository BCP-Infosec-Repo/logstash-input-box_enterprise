# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/box_enterprise"
require "timecop"
require "rspec/wait"

describe LogStash::Inputs::BoxEnterprise do

  private_key = %{
  -----BEGIN RSA PRIVATE KEY-----
  Proc-Type: 4,ENCRYPTED
  DEK-Info: AES-128-CBC,5E292076AF2B7909C68D78A2271DABFA
  
  16VO/fgqgT+xlLmso9ldpzYW850j3JDL935Gca3qow9Nt8LcmigZjYca6MZE0Rp6
  LcZBKNpvOsk4722dTFKnia0MqVRI6paYU+07gl3Dh7NJ2Y3K5wsGl9Y25yQaZG1i
  45dA8TOinvOrM0bxTKhmuHodh1GhkJwvLY4ya994Lf1LNfS3gmMMNbA1ehwCkq0V
  0+BOc/jpR2ah8k5e/MErI5meDmWxscos7yleg8lpnrTdBGE3R97Xn+0KbW6hCeow
  LaYkFoBwb4wl4nVnLjDhTBeaiCYk8NsLqaake775LW00GNF/Y+xSXTcrk/Fm/x5q
  KgSxaMXZ076QgrR3qlShmzTFeoI3hYI3OU3MOykB8aiiaKG8RT7g7vvZMd8pZvtu
  dXgS6t77VFAaB4VuQsqfpgZQRFa8RMP4TX9Eom/OC3s=
  -----END RSA PRIVATE KEY-----
  }.gsub(/^ +/m,'') # I want to have the formatting correct but also the leading spaces need to be stripped

  let(:queue) { Queue.new }
  let(:default_schedule) {
    { "every" => "30s" }
  }
  let(:default_chunk_size) { 100 }
  let(:metadata_target) { "_http_poller_metadata" }
  let(:default_client_secret_env) { "Z36nr1HVNaessT0R6SFOlk2sQFwk6" }
  let(:default_client_id) { "hwwqLg38lAsBdFgXVgNUxVl4lVovYsOd" }
  let(:default_enterprise_id) { "284423" }
  let(:default_kid) { "aiggs32v" }
  let(:default_private_key_file) { "/dev/null" }
  let(:default_private_key_pass_env) { "strong_password" }


  let(:default_opts) {
    {
      "schedule" => default_schedule,
      "chunk_size" => default_chunk_size,
      "metadata_target" => metadata_target,
      "client_secret_env" => default_client_secret_env,
      "client_id" =>  default_client_id,
      "enterprise_id" =>  default_enterprise_id,
      "kid" =>  default_kid,
      "private_key_file"  =>  default_private_key_file,
      "private_key_pass_env"  => default_private_key_pass_env,
      "codec" => "json"
    }
  }
  let(:klass) { LogStash::Inputs::BoxEnterprise }


  describe "config" do
    shared_examples "configuration errors" do
      it "raises an exception" do
        expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
      end
    end

    subject { klass.new(opts) }

    before(:each) do
      subject
    end

    context "created_after is not in the correct format" do
      let(:opts) { default_opts.merge({"created_after" => "1234567890"}) }
      include_examples("configuration errors")
    end

    context "created_before is not in the correct format" do
      let(:opts) { default_opts.merge({"created_before" => "1234567890"}) }
      include_examples("configuration errors")
    end

    context "incorrect algorithim is provided" do
      let(:opts) { default_opts.merge({"algo" => "ABC123"}) }
      include_examples("configuration errors")
    end

    context "chunk_size is too small" do
      let(:opts) { default_opts.merge({"chunk_size" => "-1"}) }
      include_examples("configuration errors")
    end

    context "chunk_size is too big" do
      let(:opts) { default_opts.merge({"chunk_size" => "501"}) }
      include_examples("configuration errors")
    end

    context "env and file management" do

      shared_examples "env and file examples" do
        context "neither env and file are provided" do
          let(:key_env) { "#{key_id}_env" }
          let(:opts) {
            opts = default_opts.clone
            opts.delete(key_env)
            opts
          }
          include_examples("configuration errors")
        end
        context "both env or file are provided" do
          let(:key_file) { "#{key_id}_file" }
          let (:opts) { default_opts.merge({key_file => "/dev/null"}) }
          include_examples("configuration errors")
        end


      end
      context "private_key_pass" do
        let(:key_id) { "private_key_pass" }
        include_examples("env and file examples")
      end

      context "client_secret" do
        let(:key_id) { "client_secret" }
        include_examples("env and file examples")

      end
    end

    context "secret file management" do
      shared_examples "secret file import tests" do
        context "file is too large" do
          before { allow(File).to receive(:size).with(opts[file_test_key]) { 10 * 2**21 } }
          include_examples("configuration errors")
        end

        context "file cannot be read" do
          before { allow(File).to receive(:read).with(opts[file_test_key]) { raise IOError } }
          include_examples("configuration errors")
        end
      end

      context "private_key_pass_file" do
        let(:file_test_key) { "private_key_pass_file" }
        let(:opts) {
          opts = default_opts.merge({"private_key_pass_file"  => "/dev/null"} ).clone
          opts.delete("private_key_pass_env")
          opts
          }
        include_examples("secret file import tests")
      end
      context "client_secret_file" do
        let(:file_test_key) {"client_secret_file"}
        let(:opts) { default_opts.merge({"client_secret_file"  => "/dev/null"} ) }
        include_examples("secret file import tests")
      end

      context "private_key_file" do
        let(:file_test_key) { "private_key_file" }
        let(:opts) { default_opts }
        include_examples("secret file import tests")
      end
    end

    context "Error loading private key" do
      let(:opts) { default_opts }
      before { allow(OpenSSL::PKey::RSA).to receive(:new) { raise OpenSSL::PKey::RSAError } }
      include_examples("configuration errors")
    end
  end

  describe "instances" do

    subject { klass.new(default_opts) }
    before do
      # Load a custom private key for testing purposes
      allow(File).to receive(:read).with(default_private_key_file) { private_key }
      subject.register
    end

    # This test fixes a bug where handle_unknown_error would generate an exception whenever the response_body was empty.
    describe "#handle_unknown_error" do

      let(:response_headers) { {:error => "there is an error status", "www-authenticate"=>"Bearer realm=\"Service\", error=\"insufficient_scope\", error_description=\"The request requires higher privileges than provided by the access token.\"", "age"=>"2", "connection"=>"keep-alive"} }
      let(:response) { Manticore::StubbedResponse.stub(body: "", headers: response_headers, code: 500).call }

      it "builds an event with an empty body" do 
        expect(subject).to receive(:apply_metadata)
        expect(subject).to receive(:decorate)
        subject.send(:handle_unknown_error, queue, response, nil, nil)
      end
    end
    describe "#run" do
      it "should setup a scheduler" do
        
        runner = Thread.new do
          subject.run(double("queue"))
          expect(subject.instance_variable_get("@scheduler")).to be_a_kind_of(Rufus::Scheduler)
        end
        runner.kill
        runner.join
      end
    end

    describe "#run_once" do
      let(:auth_token) { "" }
      let(:params_event) { {} }
      it "should issue an async request for each url" do
        expect(subject).to receive(:run_fetcher).with(queue,auth_token,params_event).once

        subject.send(:run_once, queue,auth_token,params_event) # :run_once is a private method
      end
    end
    describe "#handle_success" do

      let(:entry) { {"foo" => "bar"} }
      let(:payload) { {"entries" => [entry] } }
      let(:response_body) { LogStash::Json.dump(payload) }
      let(:response) { Manticore::StubbedResponse.stub(body: response_body, code: 200).call }
      let(:auth_token) { "asdf" }
      let(:requested_url) { subject.instance_variable_get(:@event_url) }
      let(:exec_time) { 1 }

      it "should generate an error, fixes bug" do

        allow(subject).to receive(:decorate)
        expect(subject.instance_variable_get(:@logger)).to receive(:error)
        allow(response).to receive(:times_retried) { 0 }
        subject.send(:handle_success, queue, response, auth_token, requested_url, exec_time)
        expect(subject.instance_variable_get(:@continue)).to be(false)

      end
    end
    describe "#handle_auth" do

      let(:public_key) { OpenSSL::PKey::RSA.new(private_key, default_opts['private_key_pass_env']).public_key }
      let(:header_position) { 1 }
      let(:payload_position) { 0 }
      let(:auth_token) { "" }

      context "with a valid response for an auth token" do
        let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
        let(:response_payload) { {:access_token => "#{token_payload}"} }
        let(:response_body) { LogStash::Json.dump(response_payload) }
        it "should setup the claim and modify auth_token" do

          response = Manticore::StubbedResponse.stub(body: response_body, code: 200).call
          allow(subject.client).to receive(:post) do |url, options={}|
            expect(options[:params][:client_secret]).to eq(default_opts['client_secret_env'])
            expect(options[:params][:client_id]).to eq(default_opts['client_id'])
            jwt = nil
            expect { jwt = JWT.decode(options[:params][:assertion], public_key, true ) }.not_to raise_error
            expect(jwt[payload_position]['iss']).to eq(default_opts['client_id'])
            expect(jwt[payload_position]['sub']).to eq(default_opts['enterprise_id'])
            expect(jwt[payload_position]['exp']).to be_within(30).of(Time.now.to_i)
            expect(jwt[header_position]['kid']).to eq(default_opts['kid'])
            response
          end
         
          subject.send(:handle_auth, queue, auth_token)
          expect(auth_token).to eq(token_payload)
        end
      end
      context "with an empty response from the server" do

        let(:response_body) { "" }
        it "should generate an error" do
          response = Manticore::StubbedResponse.stub(body: response_body, code: 200).call
          allow(subject.client).to receive(:post) do |url, options={}|
            expect(options[:params][:client_secret]).to eq(default_opts['client_secret_env'])
            expect(options[:params][:client_id]).to eq(default_opts['client_id'])
            jwt = nil
            expect { jwt = JWT.decode(options[:params][:assertion], public_key, true ) }.not_to raise_error
            expect(jwt[payload_position]['iss']).to eq(default_opts['client_id'])
            expect(jwt[payload_position]['sub']).to eq(default_opts['enterprise_id'])
            expect(jwt[payload_position]['exp']).to be_within(30).of(Time.now.to_i)
            expect(jwt[header_position]['kid']).to eq(default_opts['kid'])
            response
          end
          expect(subject).to receive(:handle_unknown_error)
          subject.send(:handle_auth, queue, auth_token)
        end
      end
      context "with a non-success code from the server" do
        let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
        let(:response_payload) { {:access_token => "#{token_payload}"} }
        let(:response_body) { LogStash::Json.dump(response_payload) }
        it "should generate an error" do
          response = Manticore::StubbedResponse.stub(body: response_body, code: 403).call
          allow(subject.client).to receive(:post) do |url, options={}|
            expect(options[:params][:client_secret]).to eq(default_opts['client_secret_env'])
            expect(options[:params][:client_id]).to eq(default_opts['client_id'])
            jwt = nil
            expect { jwt = JWT.decode(options[:params][:assertion], public_key, true ) }.not_to raise_error
            expect(jwt[payload_position]['iss']).to eq(default_opts['client_id'])
            expect(jwt[payload_position]['sub']).to eq(default_opts['enterprise_id'])
            expect(jwt[payload_position]['exp']).to be_within(30).of(Time.now.to_i)
            expect(jwt[header_position]['kid']).to eq(default_opts['kid'])
            response
          end
          expect(subject).to receive(:handle_unknown_error)
          subject.send(:handle_auth, queue, auth_token)
        end
      end
      context "with a timeout connecting to the server" do
        it "should generate an error" do
          allow_any_instance_of(Manticore::Client).to receive_message_chain("client.execute") { raise Manticore::SocketException }

          expect(subject).to receive(:handle_failure)
          expect(subject).not_to receive(:handle_unknown_error)
          subject.send(:handle_auth, queue, auth_token)
        end
      end
    end
  end
  describe "scheduler configuration" do

    let(:auth_token) { "" }
    let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
    before do
      # disable network connections
      allow_any_instance_of(Manticore::Client).to receive_message_chain("client.execute") { raise Manticore::SocketException }
      # Disable private key read
      allow_any_instance_of(OpenSSL::PKey::RSA).to receive(:initialize) { true }

      allow(subject).to receive(:handle_auth) do |queue, auth_token|
        auth_token.clear
        auth_token << token_payload
        auth_token
      end
      subject.register
    end

    context "given 'cron' expression" do
      let(:opts) { default_opts.merge({"schedule" => {"cron" => "* * * * * UTC"}}) }
      subject { klass.new(opts) }
      it "should run at the schedule" do
        Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
        Timecop.scale(60)
        queue = Queue.new
        runner = Thread.new do
          subject.run(queue)
        end
        sleep 3
        subject.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(2)
        Timecop.return
      end
    end
    context "given 'at' expression" do
      let(:opts) { default_opts.merge("schedule" => {"at" => "2000-01-01 00:05:00 +0000"}) }
      subject { klass.new(opts) }
      it "should run at the schedule" do
        Timecop.travel(Time.new(2000,1,1,0,0,0,'+00:00'))
        Timecop.scale(60 * 5)
        queue = Queue.new
        runner = Thread.new do
          subject.run(queue)
        end
        sleep 2
        subject.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(1)
        Timecop.return
      end
    end
    context "given 'every' expression" do
      let(:opts) { default_opts.merge("schedule" => {"every" => "2s"}) }
      subject { klass.new(opts) }
      it "should run at the schedule" do
        queue = Queue.new
        runner = Thread.new do
          subject.run(queue)
        end
        #T       0123456
        #events  x x x x
        #expects 3 events at T=5
        sleep 5
        subject.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(3)
      end
    end
    context "given 'in' expression" do
      let(:opts) { default_opts.merge("schedule" => {"in" => "2s"}) }
      subject { klass.new(opts) }
      it "should run at the schedule" do
        queue = Queue.new
        runner = Thread.new do
          subject.run(queue)
        end
        sleep 3
        subject.stop
        runner.kill
        runner.join
        expect(queue.size).to eq(1)
      end
    end
  end
  describe "events" do

    shared_examples("matching metadata") {
      let(:metadata) { event.get(metadata_target) }
      let(:options) { defined?(settings) ? settings : opts }
      let(:metadata_url) { poller.instance_variable_get("@event_url") }
      it "should have the correct request url" do
        expect(metadata["url"].to_s).to eql(metadata_url)
      end

      it "should have the correct code" do
        expect(metadata["code"]).to eql(code)
      end

    }

    shared_examples "unprocessable_requests" do
      let(:poller) { klass.new(settings) }
      let(:auth_token) { "" }
      let(:params_event) { {} }
      let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
      subject(:event) {
        poller.send(:run_once, queue, auth_token, params_event)
        queue.pop(true)
      }

      before do
        # Disable private key read
        allow_any_instance_of(OpenSSL::PKey::RSA).to receive(:initialize) { true }

        allow(poller).to receive(:handle_auth) do |queue, auth_token|
          auth_token.clear
          auth_token << token_payload
          auth_token
        end

        poller.register
        allow(poller).to receive(:handle_failure).and_call_original
        allow(poller).to receive(:handle_success)
        event
      end

      it "should enqueue a message" do
        expect(event).to be_a(LogStash::Event)
      end

      it "should enqueue a message with 'http_request_failure' set" do
        expect(event.get("http_request_failure")).to be_a(Hash)
      end

      it "should tag the event with '_http_request_failure'" do
        expect(event.get("tags")).to include('_http_request_failure')
      end

      it "should invoke handle failure exactly once" do
        expect(poller).to have_received(:handle_failure)
      end

      it "should not invoke handle success at all" do
        expect(poller).not_to have_received(:handle_success)
      end

      include_examples("matching metadata")

    end

    context "with a non responsive server" do
      context "due to a non-existent host" do # Fail with handlers
        let(:code) { nil } # no response expected
        let(:settings) { default_opts }
        before {allow_any_instance_of(Manticore::Client).to receive_message_chain("client.execute") { raise Manticore::ResolutionFailure } }

        include_examples("unprocessable_requests")
      end

    end

    describe "a valid request and decoded response" do
      let(:entry) { {"foo" => "bar"} }
      let(:payload) { {"next_stream_position" => 0, "entries" => [entry] } }
      let(:response_body) { LogStash::Json.dump(payload) }

      let(:code) { 200 }
      let(:opts) { default_opts }

      let(:auth_token) { "" }
      let(:params_event) { {} }
      let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }

      let(:instance) { klass.new(opts) }
      let(:poller) { instance }

      subject(:event) { queue.pop(true) }

      before do
        allow_any_instance_of(OpenSSL::PKey::RSA).to receive(:initialize) { true }
        allow(instance).to receive(:handle_auth) do |queue, auth_token|
          # setup for 401 test case
          unless (auth_token.empty?)
            instance.instance_variable_set("@continue", false)
          end
          auth_token.clear
          auth_token << token_payload
          auth_token
        end
        instance.register
        allow(instance).to receive(:decorate)
        instance.client.stub(%r{#{instance.instance_variable_get("@event_url")}.*},
                             :body  => response_body,
                             :code  => code
        )
        instance.send(:run_once, queue, auth_token, params_event)

      end

      it "should have a matching message" do
        expect(event.to_hash).to include(entry)
      end

      it "should decorate the event" do
        expect(instance).to have_received(:decorate).once
      end

      include_examples("matching metadata")

      context "with an empty body" do
        let(:response_body) { "" }
        it "should return an empty event" do
          expect(event.get("[_http_poller_metadata][response_headers][content-length]")).to eql("0")
        end
      end
      context "with metadata omitted" do
        let(:opts) {
          opts = default_opts.clone
          opts.delete("metadata_target")
          opts
        }

        it "should not have any metadata on the event" do
          expect(event.get(metadata_target)).to be_nil
        end
      end

      context "with a specified target" do
        let(:target) { "mytarget" }
        let(:opts) { default_opts.merge("target" => target) }

        it "should store the event info in the target" do
          # When events go through the pipeline they are java-ified
          # this normalizes the payload to java types
          payload_normalized = LogStash::Json.load(LogStash::Json.dump(entry))
          expect(event.get(target)).to include(payload_normalized)
        end
      end

      context "with non-200 HTTP response codes" do
        let(:code) { |example| example.metadata[:http_code] }
        let(:response_body) { "{}" }

        it "responds to a 500 code", :http_code => 500 do
          expect(event.to_hash).to include({"Box-Error-Code" => 500})
          expect(event.get("tags")).to include('_box_response_failure')
        end
        it "responds to a 401/Unauthorized code", :http_code => 401 do
          expect(instance).to have_received(:handle_auth).twice
        end
        it "responds to a 400 code", :http_code => 400 do
          instance.send(:run_once, queue, auth_token, params_event)
          expect(event.to_hash).to include({"Box-Error-Code" => 400})
          expect(event.get("tags")).to include('_box_response_failure')
        end
      end
    end
  end
  describe "stopping" do
    let(:config) { default_opts }
    let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
    before do
      allow_any_instance_of(OpenSSL::PKey::RSA).to receive(:initialize) { true }
      allow_any_instance_of(klass).to receive(:handle_auth) do |queue, auth_token|
        auth_token.clear
        auth_token << token_payload
        auth_token
      end
      allow_any_instance_of(Manticore::Client).to receive_message_chain("client.execute") { raise Manticore::ResolutionFailure }
    end
    it_behaves_like "an interruptible input plugin"
  end

  describe "state file" do

    let(:opts) { default_opts.merge({'state_file_base' => "/tmp/box_test_"}) }
    subject {klass.new(opts) }
    let(:state_file_position_0) { "12345678890" }
    let(:state_file_position_1) { "12345678891" }

    before do
      allow_any_instance_of(OpenSSL::PKey::RSA).to receive(:initialize) { true }
    end

    context "when being setup" do

      before do
        expect(File).to receive(:readable?).with(File.dirname(opts['state_file_base'])) { true }
        expect(File).to receive(:executable?).with(File.dirname(opts['state_file_base'])) { true }
        expect(File).to receive(:writable?).with(File.dirname(opts['state_file_base'])) { true }
        allow(subject.client).to receive_message_chain("client.execute") { raise Manticore::ResolutionFailure }
      end

      it "creates the initial file correctly" do
        expect(Dir).to receive(:[]) { [] }
        expect(File).to receive(:open).with("#{opts['state_file_base']}start","w") {}
        subject.register
      end

      it "raises an error if the file cannot be created" do
        expect(Dir).to receive(:[]) { [] }
        expect(File).to receive(:open).with("#{opts['state_file_base']}start","w") { raise IOError }
        expect {subject.register}.to raise_exception(LogStash::ConfigurationError)
      end
      it "gets the next_stream_position based on the state file" do
        allow(File).to receive(:open).with("#{opts['state_file_base']}start","w") { }
        expect(Dir).to receive(:[]) { [opts['state_file_base'] + state_file_position_0] }
        subject.register
        expect(subject.instance_variable_get("@next_stream_position")).to eql(state_file_position_0)
      end
      it "uses the latest stream position if there is more than one file" do
        allow(File).to receive(:open).with("#{opts['state_file_base']}start","w") { }
        expect(Dir).to receive(:[]) { [opts['state_file_base'] + state_file_position_0, opts['state_file_base'] + state_file_position_1] }
        subject.register
        expect(subject.instance_variable_get("@next_stream_position")).to eql(state_file_position_1)
      end
      it "does not set next_stream_position if the file is start" do
        expect(Dir).to receive(:[]) { [opts['state_file_base'] + "start"] }
        subject.register
        expect(subject.instance_variable_get(:@next_stream_position)).to be(nil)
      end
    end
    context "when running" do
      let(:entry) { {"foo" => "bar"} }
      let(:payload) { {"next_stream_position" => state_file_position_0, "entries" => [entry] } }
      let(:response_body) { LogStash::Json.dump(payload) }
      let(:auth_token) { "" }
      let(:token_payload) { "J2iageHCXuHi4rOL3BXIiEJqUW" }
      let(:params_event) { {} }

      let(:code) { 200 }

      before(:each) do

        allow(Dir).to receive(:[]) { [opts['state_file_base'] + "start"] }

        subject.register
        subject.client.stub(%r{#{subject.instance_variable_get("@event_url")}.*},
                             :body  => response_body,
                             :code  => code
        )

        allow(subject).to receive(:handle_failure) { subject.instance_variable_set(:@continue, false) }

        allow(subject).to receive(:handle_auth) do |queue, auth_token|
          auth_token.clear
          auth_token << token_payload
          auth_token
        end

      end

      it "updates the state file after data is fetched" do

        expect(File).to receive(:rename).with(opts['state_file_base'] + "start", opts['state_file_base'] + state_file_position_0) { 0 }
        subject.send(:run_once, queue,auth_token,params_event) # :run_once is a private method

      end
      it "leaves the state file alone during a failure" do

        subject.client.clear_stubs!
        allow(subject.client).to receive_message_chain("client.execute") { raise Manticore::ResolutionFailure }
        expect(File).not_to receive(:rename).with(opts['state_file_base'] + "start", any_args)
        subject.send(:run_once, queue, auth_token, params_event) # :run_once is a private method


      end

      context "when stop is called" do

        it "saves the state in the file name" do

          # We are still testing the same condition, file renaming.
          expect(File).to receive(:rename).with(opts['state_file_base'] + "start", opts['state_file_base'] + state_file_position_0) { 0 }

          # Force a sleep to make the thread hang in the failure condition.
          allow(subject).to receive(:decorate) do
            subject.instance_variable_set(:continue, false)
            sleep(30)
          end

          plugin_thread = Thread.new(subject, queue) { |subject, queue, auth_token, params_event | subject.send(:run, queue) }

          # Sleep for a bit to make sure things are started.
          sleep 0.5
          expect(plugin_thread).to be_alive

          subject.do_stop

          # As they say in the logstash thread, why 3?
          # Because 2 is too short, and 4 is too long.
          wait(3).for {plugin_thread }.to_not be_alive
        end
      end
    end
  end
end
