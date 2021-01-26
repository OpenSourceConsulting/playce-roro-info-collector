from ..ssh.sshBase import *
from .RhelFacts import *
from .DebianFacts import *

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException

    HAS_PARAMIKO = True
except ImportError:
    print("Error : Failed to import Paramiko module")
    HAS_PARAMIKO = False


class LinuxFactorGenerator:
    def __init__(self, params):
        LogManager.set_logging(params.get('logDir'))
        self.ssh = SshBase()
        self.ssh.connect(params)
        os_release = self.get_distribution_Linux()

        if 'CentOS' in os_release or 'Red Hat' in os_release or 'AMI' in os_release:
            self.factor = RhelFacts(params, os_release)
        else:
            self.factor = DebianFacts(params, os_release)

    def get_distribution_Linux(self):
        out = self.ssh.run_command("cat /etc/*-release | grep PRETTY_NAME")

        if len(out) > 1:
            data = out.split("=")
            result = re.sub('\n|"', '', data[1])
            return result

        return 'None'

    def get_info(self):
        self.factor.execute()

    def get_results(self):
        self.factor.get_results()
