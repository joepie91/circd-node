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
		if @server.hasUser(@nickname)
			# Race condition occurred, abort.
			return @abortConnection("Nickname is already in use.") # FIXME
		@server.setUser(@nickname, this)
		@sendWelcome()
		@sendMOTD()
		
	onDisconnected: (reason) =>
		# FIXME: Broadcast disconnect
		@server.deleteUser(@nickname)
		
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
						if @server.hasUser(segments[1])
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
					if segments[0] of @process_map
						@sendError(451, segments[0], "You have not registered.")
					else
						@sendError(421, segments[0], "Unknown command")
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
		
	sendCommand: (data, source = null) =>
		source = source ? @server.host
		@sendRaw(":#{source} #{data}")
		
	sendPing: (value) =>
		@sendRaw("PING :#{value}")
		
	sendPong: (value) =>
		@sendRaw("PONG :#{value}")
		
	sendNumeric: (numeric, message) =>
		@sendCommand("#{numeric} #{@nickname} #{message}")
		
	sendNumericNotice: (numeric, message) =>
		@sendNumeric(numeric, ":#{message}")
		
	sendGlobalNotice: (message) =>
		@sendCommand("NOTICE #{message}")
		
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
			
	getIdentity: (nickname, always_hash = false) =>
		if not @server.hasUser(nickname)
			throw new NicknameNotInUseException("The specified source nickname is not currently in use.")
		
		user = @server.getUser(nickname)

		ident = user.ident

		if Util.toLowercaseIRC(nickname) == Util.toLowerCase(@nickname) and always_hash == false
			host = @real_reverse # This way the real host can *never* leak, even if somebody messes with the identity check
		else
			host = user.reverse

		return "#{ident}@#{host}"

	getFullIdentity: (nickname, always_hash = false) =>
		identity = @getIdentity(nickname, always_hash)
		return "#{nickname}!#{identity}"
	
	processNickChange: (segments) =>
		new_nickname = segments[1]
		old_nickname = @nickname
		old_identity = @getFullIdentity(old_nickname, true)
		
		if nickname == @nickname
			return
		else
			try
				@server.renameUser(old_nickname, new_nickname)
			catch err
				if err instanceof NicknameInUseException
					return @sendError(433, nickname, "Nickname is already in use.")
				if err instanceof NicknameNotInUseException
					# FIXME: Log error, this is a bug!
					
		@sendCommand("NICK :#{nickname}", old_identity) # FIXME: Broadcast NICK change to all affected users! REQ: Channels
	
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
		
		