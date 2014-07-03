net = require("net")

class Server
	constructor: () ->
		# TODO: Add webirc configuration blocks
		@bindings = []
		@clients = []
		@users = {} # Contains all clients that have registered, indexed by nickname
		@channels = {}
		@host = "localhost" # FIXME
		@network = "Cryto IRC" # FIXME
		@motd = "This is purely a testing MOTD." # FIXME
		@password = null # FIXME
		
	bind: (bind_ip, port, tls = false, options = {}) =>
		@bindings.push({
			bind_ip: bind_ip,
			port: port,
			tls: tls,
			options: options
		})
		
	start: =>
		for binding in @bindings
			if binding.tls
				binding.socket = tls.createServer(@onConnected, binding.options)
			else
				binding.socket = net.createServer(@onConnected, binding.options)
			
			binding.socket.on("listening", => console.log("Listening on #{binding.bind_ip}:#{binding.port}"))
			binding.socket.on("error", (e) => @onError(binding, e))
			binding.socket.listen(binding.port, binding.bind_ip)
		
	onConnected: (connection) =>
		client = new Client(this, connection)
		@clients.push(client)
		client.initialize()
		
	onError: (binding, e) =>
		if e.code == "EADDRINUSE"
			binding.socket.close()
			# FIXME: Log an error?
			
	hasUser: (nickname) =>
		nickname = Util.toLowercaseIRC(nickname)
		return nickname of @users
			
	getUser: (nickname) =>
		nickname = Util.toLowercaseIRC(nickname)
		return @users[nickname] ? null
	
	setUser: (nickname, user) =>
		if not Util.isValidNickname(nickname)
			Util.throwError("InvalidNickname", "The nickname contains invalid characters.")
		nickname = Util.toLowercaseIRC(nickname)
		@users[nickname] = user
		
	deleteUser: (nickname) =>
		nickname = Util.toLowercaseIRC(nickname)
		delete @users[nickname]
		
	renameUser: (old_nickname, new_nickname) =>
		if not Util.isValidNickname(new_nickname)
			Util.throwError("InvalidNickname", "The new nickname contains invalid characters.")
			
		old_nickname = Util.toLowercaseIRC(old_nickname)
		new_nickname = Util.toLowercaseIRC(new_nickname)
		
		if not @hasUser(old_nickname)
			Util.throwError("NicknameNotInUse", "The specified source nickname is not currently in use.")
			
		if @hasUser(new_nickname)
			Util.throwError("NicknameInUse", "The specified target nickname is in use by another user.")
		
		@users[new_nickname] = @users[old_nickname]
		delete @users[old_nickname]
	
	authenticateOper: (hostname, username, password) =>
		# TODO: @authenticateOper