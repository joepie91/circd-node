net = require("net")

class Server
	constructor: () ->
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