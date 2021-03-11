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
        os_version = self.get_version()

        self.ssh.close()

        if 'CentOS' in os_release or 'Red Hat' in os_release or 'AMI' in os_release:
            self.factor = RhelFacts(params, os_release, os_version)
        else:
            self.factor = DebianFacts(params, os_release, os_version)

    def get_distribution_Linux(self):
        os_release = self.ssh.run_command("cat /etc/os-release")
        if os_release:
            for line in os_release.splitlines():
                if 'PRETTY_NAME' in line:
                    return line.split("=")[1]

        system_release = self.ssh.run_command("cat /etc/system-release")
        if system_release:
            for line in system_release.splitlines():
                return line

        return 'None'

    def get_version(self):
        os_release = self.ssh.run_command("cat /etc/os-release")
        os_version = ""
        if os_release:
            for line in os_release.splitlines():
                if 'VERSION' in line:
                    os_version = re.findall("\d+", line)
                    break
            return os_version[0]

        system_release = self.ssh.run_command("cat /etc/system-release")
        if system_release:
            os_version = re.findall("\d+", system_release)
            return os_version[0]

        redhat_release = self.ssh.run_command("cat /etc/redhat-release")
        if redhat_release:
            for line in redhat_release.splitlines():
                if 'Red Hat Enterprise Linux Server release' in line:
                    os_version = re.findall("\d+", line)
                    break
            return os_version[0]

        lsb_release = self.ssh.run_command("cat /etc/lsb-release")
        if lsb_release:
            for line in lsb_release.splitlines():
                if "DISTRIB_RELEASE" or "DISTRIB_DESCRIPTION" in line:
                    os_version = re.findall("\d+", line)
                    break
            return os_version[0]

        hostnamectl = self.ssh.run_command("hostnamectl | grep Operating")
        if hostnamectl:
            os_version = re.findall("\d+", hostnamectl)
            return os_version[0]

        return None


    def get_info(self):
        self.factor.execute()

    def get_results(self):
        self.factor.get_results()
