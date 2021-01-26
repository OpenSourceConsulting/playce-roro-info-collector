from ..ssh.sshBase import *
from .AixFacts import *
from .HPFacts import *

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException

    HAS_PARAMIKO = True
except ImportError:
    print("Error : Failed to import Paramiko module")
    HAS_PARAMIKO = False


class UnixFactorGenerator:
    def __init__(self, params):
        LogManager.set_logging(params.get('logDir'))
        self.ssh = SshBase(isSudo=False)
        self.ssh.connect(params)
        os_release = self.get_distribution_Unix()

        if 'AIX' in os_release:
            self.factor = AixFacts(params, os_release)
        else:
            self.factor = HPFacts(params, os_release)

    def get_distribution_Unix(self):
        out = self.ssh.run_command("/usr/bin/uname -a")

        if out:
            data = out.split()
            return data[0]

        return 'None'

    def get_info(self):
        self.factor.execute()

    def get_results(self):
        self.factor.get_results()
