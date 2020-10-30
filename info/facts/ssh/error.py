class ShellError(Exception):

  def __init__(self, msg, command=None):
    super(ShellError, self).__init__(msg)
    self.command = command