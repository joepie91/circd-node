Util = 
	parseMessage: (message) ->
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