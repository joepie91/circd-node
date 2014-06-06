dns = require("dns")
q = require("q")
crypto = require("crypto")

ClientStatus = {
	"disconnected": 0
	"lookingUp": 1
	"connected": 2
	"registered": 3
	"ready": 4
}

class Client
	constructor: (@server, @connection) ->
		@status = ClientStatus.disconnected
		@buffer = ""
		
	initialize: =>
		@process_map = {
			"USERHOST": [1, @processUserhost]
			"WHO": [1, @processWho]
		}
		
		@connection.on("data", @onData)
		@status = ClientStatus.lookingUp
		@sendGlobalNotice("AUTH :*** Looking up your hostname...")
		q.nfcall(dns.reverse, @connection.remoteAddress).then(@onLookupSuccess, @onLookupError)
		
	onLookupSuccess: (hosts) =>
		if hosts.length == 0
			return @onLookupError(null)
		host = hosts[0]
		@status = ClientStatus.connected
		@reverse = @maskHost(host)
		@real_reverse = host
		@sendGlobalNotice("AUTH :*** Found your hostname")
		
	onLookupError: (e) =>
		@status = ClientStatus.connected
		@reverse = @maskIP(@connection.remoteAddress)
		@real_reverse = @connection.remoteAddress
		@sendGlobalNotice("AUTH :*** Could not find your hostname, using IP address instead")
		
	onChallengeCompleted: =>
		@status = ClientStatus.ready
		@onConnectionCompleted()
		
	onConnectionCompleted: =>
		if Util.toLowercaseIRC(@nickname) of @server.users
			# Race condition occurred, abort.
			return @abortConnection("Nickname is already in use.") # FIXME
		@server.users[Util.toLowercaseIRC(@nickname)] = this
		@sendWelcome()
		@sendMOTD()
		
	onDisconnected: (reason) =>
		# FIXME: Broadcast disconnect
		delete @server.users[Util.toLowercaseIRC(@nickname)]
		
	onData: (data) =>
		@buffer += data
		messages = @buffer.split("\n")
		@buffer = messages.pop()
		@onMessage(message.replace(Util.regex_strip_carriage_return, "")) for message in messages
		
	onMessage: (message) =>
		segments = Util.parseMessage(message)
		segments[0] = segments[0].toUpperCase()
		
		if @status == ClientStatus.connected
			switch segments[0]
				when "USER"
					if segments.length < 5
						@sendError(461, "USER", "Not enough parameters.")
					else
						@ident = segments[1]
						@realname = segments[4]
						@verifyRegistration()
				when "NICK"
					if segments.length < 2
						@sendError(461, "NICK", "Not enough parameters.")
					else
						if Util.toLowercaseIRC(segments[1]) of @server.users
							@sendError(433, segments[1], "Nickname already in use.")
						else
							@nickname = segments[1]
							@verifyRegistration()
				when "PASS"
					if segments.length < 2
						@sendError(461, "NICK", "Not enough parameters.")
					else
						@server_password = segments[1]
						@verifyRegistration()
				when "PONG"
					null # Ignore
				else
					@sendError(451, segments[0], "You have not registered.")
		else if @status == ClientStatus.registered
			if segments[0] == "PONG"
				if segments.length < 2
					@sendError(461, "PONG", "Not enough parameters.")
				else
					if segments[1] == @challenge
						@onChallengeCompleted()
					else
						@sendError(801, segments[0], "Your challenge response PONG is incorrect.")
			else
				@sendError(451, segments[0], "You have not completed the challenge PING.")
		else if @status == ClientStatus.ready
			if segments[0] == "PING"
				if segments.length < 2
					@sendError(461, "PONG", "Not enough parameters.")
				else
					@sendPong(segments[1])
			else
				if segments[0] of @process_map
					[min_args, func] = @process_map[segments[0]]
					if segments.length < min_args + 1
						@sendError(461, segments[0], "Not enough parameters.")
					else
						func(segments)
				else
					@sendError(421, segments[0], "Unknown command")
					
				
	verifyRegistration: =>
		if @ident? and @nickname?
			if @server.password?
				if @server.password != @server_password
					return @sendError(464, null, "Password incorrect.")
			@status = ClientStatus.registered
			@sendChallenge()

	maskIP: (ip) =>
		return ip # FIXME: Actually hash this value
		
	maskHost: (host) =>
		return host # FIXME: Actually hash this value
		
	sendRaw: (data) =>
		@connection.write(data + "\r\n")
		
	sendPing: (value) =>
		@sendRaw("PING :#{value}")
		
	sendPong: (value) =>
		@sendRaw("PONG :#{value}")
		
	sendNumeric: (numeric, message) =>
		@sendRaw(":#{@server.host} #{numeric} #{@nickname} #{message}")
		
	sendNumericNotice: (numeric, message) =>
		@sendNumeric(numeric, ":#{message}")
		
	sendGlobalNotice: (message) =>
		@sendRaw(":#{@server.host} NOTICE #{message}")
		
	sendError: (numeric, argument, message) =>
		# `argument` is the faulty input that the error applies to. This can be a
		# command, nickname, etc.
		if argument?
			@sendNumeric(numeric, "#{argument} :#{message}")
		else
			@sendNumericNotice(numeric, message)
		
	sendChallenge: =>
		q.nfcall(crypto.randomBytes, 6).then(
			(bytes) => bytes = bytes.toString("hex"); @challenge = bytes; @sendPing(bytes)
			(error) => @disconnect(error)
		)

	sendWelcome: =>
		@sendNumericNotice("001", "Welcome to #{@server.network}, #{@nickname}!#{@ident}@#{@real_reverse}")
		@sendNumericNotice("002", "Your host is #{@server.host}, running circd/0.0.1") # FIXME: Version!
		@sendNumericNotice("003", "This server has been running since unknown.") # FIXME: Daemon start time
		@sendNumericNotice("004", "#{@server.host} circd/0.0.1  ") # FIXME: Version and modes!
		
	sendMOTD: =>
		if @server.motd
			@sendNumericNotice(375, "- #{@server.host} Message of the day - ")
			for line in Util.splitLines(@server.motd)
				@sendNumericNotice(372, "- #{line}")
			@sendNumericNotice(376, "End of MOTD command")
		else
			@sendNumericNotice(422, "MOTD File is missing")
				
		
	getIdentity: (nickname) =>
		ident = @ident # FIXME
		
		if nickname == @nickname
			host = @real_reverse
		else
			host = @reverse # FIXME
			
		return "#{ident}@#{host}"
	
	processUserhost: (segments) =>
		nicknames = segments.slice(1)
		responses = []
		
		for nickname in nicknames
			identity = @getIdentity(nickname)
			responses.push("#{nickname}=+#{identity}")
			
		remaining_slots = 5 - segments.length
		if remaining_slots >= 2
			# Pad the response like UnrealIRCd does
			pads = remaining_slots - 1
			for i in [0..pads]
				responses.push("")
		
		@sendNumeric("302", responses.join(" "))
		
	processWho: (segments) =>
		query = segments[0]
		modifiers = segments[1].split() ? []
		
		