import socket
import sys
import os
from info.facts.log.LogManager import LogManager
from error import *

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException

    HAS_PARAMIKO = True
except ImportError:
    print("Error : Failed to import Paramiko module")
    HAS_PARAMIKO = False


class SshBase(object):
    def __init__(self, prompts_re=None, errors_re=None, kickstart=True, isSudo=True):
        self.ssh = None
        self.kickstart = kickstart
        self.isSudo = isSudo

    def open(self, host, port=22, username=None, password=None, timeout=10,
             key_filename=None, pkey=None, look_for_keys=None,
             allow_agent=False, key_policy="missing"):

        self.ssh = paramiko.SSHClient()

        if username == "root":
            self.isSudo = False

        if key_policy != "ignore":
            self.ssh.load_system_host_keys()
            try:
                self.ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            except IOError:
                pass

        if key_policy == "strict":
            self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif key_policy == "missing":
            self.ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        else:
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if not look_for_keys:
            look_for_keys = password is None

        try:
            self.ssh.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, look_for_keys=look_for_keys, pkey=pkey,
                key_filename=key_filename, allow_agent=allow_agent,
            )

        except socket.gaierror:
            raise ShellError("unable to resolve host name")
        except AuthenticationException:
            raise ShellError('Unable to authenticate to remote device')
        except socket.timeout:
            raise ShellError("timeout trying to connect to remote device")
        except socket.error:
            raise ShellError('timeout trying to connect to host')

    @LogManager.logging
    def connect(self, params, kickstart=True):
        host = params.get('host')
        port = params.get('port') or 22

        username = params.get('username')
        password = params.get('password')
        key_filename = params.get('ssh_keyfile') or None
        timeout = params.get('timeout') or 10

        try:
            self.open(
                host=host, port=int(port), username=username, password=password,
                timeout=timeout, key_filename=key_filename,
            )

        except ShellError as err:
            print str(err)
            sys.exit(2)

        self._connected = True

    # @LogManager.logging
    def run_command(self, command):
        # option = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no '

        if self.isSudo:
            stdin, stdout, stderr = self.ssh.exec_command("/usr/bin/sudo " + command)
        else:
            stdin, stdout, stderr = self.ssh.exec_command(command)

        try:
            all_out = ''
            all_err = ''

            stdout = stdout.readlines()
            stderr = stderr.readlines()

            stdout = [line.encode("utf-8") for line in stdout]
            # stderr = [str(unicode(line, 'utf-8')) for line in stderr]

            for line in stdout:
                all_out = all_out + line

            for line in stderr:
                all_err = all_err + line
            '''
      while not stdout.channel.exit_status_ready():
          # Print stdout data when available
          if stdout.channel.recv_ready():
              # Retrieve the first 1024 bytes
              #all_out = stdout.channel.recv(1024)
              #all_err = stderr.channel.recv(1024)
              all_out = stdout.read()
              all_err = stderr.read()
              #while stdout.channel.recv_ready():
                  # Retrieve the next 1024 bytes
                  #all_out += stdout.channel.recv(1024)

              #while stderr.channel.recv_ready():
                  # Retrieve the next 1024 bytes
                  #all_err += stderr.channel.recv(1024)
      '''
        except Exception as e:
            LogManager.logger.error("Failed %s, command : [%s]" % str(e), command)
            sys.exit(3)

        finally:
            return all_out

    def run_dump_command(self, params):
        try:
            command = (
                        "nohup /bin/dd if=%s bs=%s count=%s | ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i %s %s@%s dd of=%s/%s > /tmp/%s_dump.log&"
                        % (params['device'], "512", params['blockend'], params['target_keyfile'], params['target_user'],
                           params['target_host'], params['target_path'], params['target_filename'],
                           params['target_filename']))

            self.run_command(command)
        except ShellError:
            print("Dump command executing error!!")

    def close(self):
        self.ssh.close()
