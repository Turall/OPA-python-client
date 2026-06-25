class ConnectionsError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class QueryExecuteError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class PolicyNotFoundError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class CheckPermissionError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class DeleteDataError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class DeletePolicyError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class PathNotFoundError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class RegoParseError(Exception):
	def __init__(self, expression, message, errors=None):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		errors -- optional list of detailed OPA compilation errors
		"""
		self.expression = expression
		self.message = message
		self.errors = errors or []

	def __str__(self):
		if self.errors:
			details = "; ".join(
				err.get("message", "")
				for err in self.errors
				if isinstance(err, dict) and err.get("message")
			)
			if details:
				return f"({self.expression}, {self.message}: {details})"
		return f"({self.expression}, {self.message})"


class SSLError(Exception):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class FileError(ValueError):
	def __init__(self, expression, message):
		"""
		expression -- input expression in which the error occurred
		message -- explanation of the error
		"""
		self.expression = expression
		self.message = message


class TypeException(TypeError):
	def __init__(self, expression):
		"""
		expression -- input expression in which the error occurred
		"""
		self.expression = expression
