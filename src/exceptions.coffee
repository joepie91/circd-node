class NicknameInUseException extends Error
	# Thrown when a nickname conflict occurs (eg. when specifying a NICK that is in use by another user)
	name: "NicknameInUse"
	
class NicknameNotInUseException extends Error
	# Thrown when an existing nickname was expected, but the given nickname isn't actually in use.
	name: "NicknameNotInUse"