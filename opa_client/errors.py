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
    def __init__(self, expression, message):
        """
        expression -- input expression in which the error occurred
        message -- explanation of the error
        """
        self.expression = expression
        self.message = message


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


class TypeExecption(TypeError):
    def __init__(self, expression):
        """
        expression -- input expression in which the error occurred
        """
        self.expression = expression
