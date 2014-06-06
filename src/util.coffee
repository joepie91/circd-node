Util = 
	nickname_regex: /[a-zA-Z\[\]\\`_^{|}][a-zA-Z0-9\[\]\\`_^{|}-]*/
	regex_strip_carriage_return: /\r+$/
	
	parseMessage: (message) ->
		# Strip the prefix, if it's present
		if message.substring(0, 1) == ":"
			message = message.split(" ").slice(1).join(" ")
		# Parse the remainder of the message
		halves = Util.singleSplit(message, ":")
		if halves.length > 1
			segments = halves[0].split(" ").concat([halves[1]])
		else
			segments = halves[0].split(" ")
		return (segment.trim() for segment in segments when segment.trim() isnt "")
		
	singleSplit: (string, separator) ->
		# Because the 'limit' implementation in standard JS split is worthless...
		index = string.indexOf(separator)
		if index >= 0
			return [string.slice(0, index), string.slice(index + 1)]
		else
			return [string]
		
	splitChannelNames: (names) ->
		return names.split(",")
	
	splitLines: (string) ->
		return (line.replace(Util.regex_strip_carriage_return, "") for line in string.split("\n"))
		
	isChannelName: (name) ->
		return name.substring(0, 1) in ["&", "#", "+", "!"]
	
	isValidChannelName: (name) ->
		for char in [" ", ",", "\x00", "\x07", "\r", "\n"] # Forbidden characters
			return false if name.indexOf(char) >= 0
		return Util.isChannelName(name)
	
	isValidNickname: (name) ->
		# Because Unicode lookalike characters are a validation nightmare, we'll only allow simple ASCII here.
		# We also don't institute any nickname length limitations; this is up to the server configuration.
		return Util.nickname_regex.test(name)
	
	toLowercaseIRC: (string) ->
		###
		 http://tools.ietf.org/html/rfc2812#section-2.2
		 
		 "Because of IRC's Scandinavian origin, the characters {}|^ are
		  considered to be the lower case equivalents of the characters []\~,
		  respectively. This is a critical issue when determining the
		  equivalence of two nicknames or channel names."

		 Yeah, don't ask me. I don't understand either.
		###
		
		return string.toLowerCase().replace("[", "{").replace("]", "}").replace("\\", "|").replace("~", "^")
	
	filterByMask: (collection, mask, property = null) ->
		escaped = Util.escapeCharacters(mask, ["\\", "^", "$", "{", "}", "[", "]", "(", ")", ".", "|", "+", "<", ">", "-", "&"])
		re = new RegExp(escaped.replace("*", ".*").replace("?", "."))
		if property?
			return (item for item in collection if re.test(item[property]))
		else
			return (item for item in collection if re.test(item))
		
	escapeCharacters: (string, characters) ->
		for character in characters
			string = string.replace(character, "\#{character}")
		return string