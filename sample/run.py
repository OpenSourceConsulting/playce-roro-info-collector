
'''
RORO Migration - AIX Info gatter

Example usage :

./run.py --source=<Source Host IP> --user=<User> --password=<Password>

'''

__author__ = 'Jinyoung Yeom'

import argparse
import simplejson as json
import os
import re
import socket
import struct
import sys
import time
import StringIO

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException
    HAS_PARAMIKO = True
except ImportError:
    print("Error : Failed to import Paramiko module")
    HAS_PARAMIKO = False

ANSI_RE = [
    re.compile(r'(\x1b\[\?1h\x1b=)'),
    re.compile(r'\x08.')
]

def to_list(val):
    if isinstance(val, (list, tuple)):
        return list(val)
    elif val is not None:
        return [val]
    else:
        return list()


class ShellError(Exception):

    def __init__(self, msg, command=None):
        super(ShellError, self).__init__(msg)
        self.command = command


class SshBase(object):
    def __init__(self, prompts_re=None, errors_re=None, kickstart=True):
        self.ssh = None
        self.kickstart = kickstart


    def open(self, host, port=22, username=None, password=None, timeout=10,
             key_filename=None, pkey=None, look_for_keys=None,
             allow_agent=False, key_policy="loose"):

        self.ssh = paramiko.SSHClient()

        if key_policy != "ignore":
            self.ssh.load_system_host_keys()
            try:
                self.ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            except IOError:
                pass

        if key_policy == "strict":
            self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
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


    def run_command(self, command):
        stdin, stdout, stderr = self.ssh.exec_command('/usr/bin/sudo ' + command)

        try:
            all_out = ''
            all_err = ''

            stdout = stdout.readlines()

            for line in stdout:
                all_out = all_out + line

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
        except ShellError as e:
            print("Failed %s, command : [%s]" % str(e), command)
            sys.exit(3)

        finally:
            return all_out

    def run_dump_command(self, params):
        try:
            command = ("nohup /bin/dd if=%s bs=%s count=%s | ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i %s %s@%s dd of=%s/%s > /tmp/%s_dump.log&"
                 % (params['device'], "512", params['blockend'], params['target_keyfile'], params['target_user'],
                 params['target_host'], params['target_path'], params['target_filename'], params['target_filename']))

            self.run_command(command)
        except ShellError:
            print("Dump command executing error!!")

    def close(self):
        self.ssh.close()

class AIX(object):
    """
    AIX-specific subclass of Hardware.
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count
    """
    platform = 'AIX'

    def __init__(self, params, prompts_re=None, errors_re=None, kickstart=True):
        self.ssh = SshBase(params)
        self.ssh.connect(params)
        self.kickstart = kickstart
        self.facts = {}

    def populate(self):
        try:
            self.get_distribution_AIX()
            self.get_hostname()
            self.get_cpu_facts()
            self.get_memory_facts()
            self.get_kernel()
            self.get_bitmode()
            self.get_dmi_facts()
            self.get_interfaces_info()
            self.get_vgs_facts()
            self.get_users()
            self.get_groups()
            self.get_password_of_users()
            self.get_ulimits()
            self.get_crontabs()
            self.get_default_interfaces()
            self.get_df()
            self.get_extra_partitions()
            self.get_ps_lists()
#            self.get_kernel_parameters()

        except Exception as err:
            print str(err)

        finally :
            return self.facts

    def get_results(self):
        r = json.dumps(self.facts)
        print r
        return r

    def get_distribution_AIX(self):
        out = self.ssh.run_command("/usr/bin/oslevel")
        data = out.split('.')
        self.facts['distribution_version'] = data[0]
        self.facts['distribution_release'] = data[1]

    def get_hostname(self):
        out = self.ssh.run_command("/usr/bin/hostname")
        self.facts['hostname'] = out.replace('\n','')

    def get_cpu_facts(self):
        self.facts['processor'] = []

        out = self.ssh.run_command("/usr/sbin/lsdev -Cc processor")
        if out:
            i = 0
            for line in out.splitlines():
                if 'Available' in line:
                    if i == 0:
                        data = line.split(' ')
                        cpudev = data[0]
                    i += 1

            self.facts['processor_count'] = int(i)

            out = self.ssh.run_command("/usr/sbin/lsattr -El " + cpudev + " -a type")

            data = out.split(' ')
            self.facts['processor'] = data[1]

            out = self.ssh.run_command("/usr/sbin/lsattr -El " + cpudev + " -a smt_threads")

            data = out.split(' ')
            self.facts['processor_cores'] = int(data[1])

    def get_memory_facts(self):
        pagesize = 4096
        out = self.ssh.run_command("/usr/bin/vmstat -v")
        for line in out.splitlines():
            data = line.split()
            if 'memory pages' in line:
                pagecount = int(data[0])
            if 'free pages' in line:
                freecount = int(data[0])
        self.facts['memtotal_mb'] = pagesize * pagecount // 1024 // 1024
        self.facts['memfree_mb'] = pagesize * freecount // 1024 // 1024

        # Get swapinfo.  swapinfo output looks like:
        # Total Paging Space   Percent Used
        #       2048MB               0%
        #
        out = self.ssh.run_command("/usr/sbin/lsps -s")
        if out:
            lines = out.splitlines()
            data = lines[1].split()
            swaptotal_mb = int(data[0].rstrip('MB'))
            percused = int(data[1].rstrip('%'))
            self.facts['swaptotal_mb'] = swaptotal_mb
            self.facts['swapfree_mb'] = int(swaptotal_mb * ( 100 - percused ) / 100)

    def get_kernel(self):
        out = self.ssh.run_command("lslpp -l | grep bos.mp")

        lines = out.splitlines()
        data = lines[0].split()

        self.facts['kernel'] = data[1]

    def get_bitmode(self):
        out = self.ssh.run_command("getconf KERNEL_BITMODE")
        self.facts['architecture'] = out.replace('\n','')

    def get_dmi_facts(self):
        out = self.ssh.run_command("/usr/sbin/lsattr -El sys0 -a fwversion")
        data = out.split()
        self.facts['firmware_version'] = data[1].strip('IBM,')

        out = self.ssh.run_command("/usr/sbin/lsconf")
        if out:
            for line in out.splitlines():
                data = line.split(':')
                if 'Machine Serial Number' in line:
                    self.facts['product_serial'] = data[1].strip()
                if 'LPAR Info' in line:
                    self.facts['lpar_info'] = data[1].strip()
                if 'System Model' in line:
                    self.facts['product_name'] = data[1].strip()

    def get_df(self):
        out = self.ssh.run_command("/usr/bin/df -m")

        if out:
            self.facts['partitions'] = {}
            regex = re.compile(r'^/dev/', re.IGNORECASE)
            for line in out.splitlines():
                if regex.match(line):
                    pt = line.split()
                    self.facts['partitions'][pt[6]] = dict(device = pt[0], fstype = self.get_fs_type(pt[0]), size = pt[1], free = pt[2])

    def get_fs_type(self, device):
        short_device_name = device.split('/')[2]

        cmd = "/usr/sbin/lsvg -l rootvg"
        out = self.ssh.run_command(cmd)

        for line in out.splitlines():
            if re.match(("^%s" % short_device_name), line):
                return line.split()[1]

    def get_extra_partitions(self):
        root_partitions = ['N/A', '/', '/usr', '/var', '/tmp', '/home', '/proc', '/opt', '/admin', '/var/adm/ras/livedump']

        out = self.ssh.run_command("/usr/sbin/lsvg -l rootvg")

        if out:
            self.facts['extra_partitions'] = {}
            for line in out.splitlines():
                data = line.split()
                if data[0] in 'rootvg:' or data[0] in 'LV':
                    continue

                self.facts['extra_partitions'][data[6]] = \
                  dict(mount_point = data[0], type=data[1], lv_state = data[5], extra = 'False')

                if data[6] not in root_partitions:
                    self.facts['extra_partitions'][data[6]] = \
                      dict(mount_point = data[0], type=data[1], lv_state = data[5], extra = 'True')

    def get_vgs_facts(self):
        """
        Get vg and pv Facts
        rootvg:
        PV_NAME           PV STATE          TOTAL PPs   FREE PPs    FREE DISTRIBUTION
        hdisk0            active            546         0           00..00..00..00..00
        hdisk1            active            546         113         00..00..00..21..92
        realsyncvg:
        PV_NAME           PV STATE          TOTAL PPs   FREE PPs    FREE DISTRIBUTION
        hdisk74           active            1999        6           00..00..00..00..06
        testvg:
        PV_NAME           PV STATE          TOTAL PPs   FREE PPs    FREE DISTRIBUTION
        hdisk105          active            999         838         200..39..199..200..200
        hdisk106          active            999         599         200..00..00..199..200
        """

        lsvg_path = "/usr/sbin/lsvg"
        xargs_path = "/usr/bin/xargs"
        cmd = "%s | %s %s -p" % (lsvg_path ,xargs_path,lsvg_path)
        if lsvg_path and xargs_path:
            out = self.ssh.run_command(cmd)
            if out:
                self.facts['vgs']= {}
                for m in re.finditer(r'(\S+):\n.*FREE DISTRIBUTION(\n(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*)+', out):
                    self.facts['vgs'][m.group(1)] = []
                    pp_size = 0
                    cmd = "%s %s" % (lsvg_path,m.group(1))
                    out = self.ssh.run_command(cmd)
                    if out:
                        pp_size = re.search(r'PP SIZE:\s+(\d+\s+\S+)',out).group(1)
                        for n in  re.finditer(r'(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*',m.group(0)):
                            pv_info = { 'pv_name': n.group(1),
                                        'pv_state': n.group(2),
                                        'total_pps': n.group(3),
                                        'free_pps': n.group(4),
                                        'pp_size': pp_size
                                      }
                            self.facts['vgs'][m.group(1)].append(pv_info)

    def get_users(self):
        # List of users excepted
        except_users=['daemon', 'bin', 'sys', 'adm', 'uucp', 'guest', 'nobody', 'lpd',
                      'lp', 'invscout', 'snapp', 'ipsec', 'nuucp', 'sshd', 'ftp', 'anonymou']

        out = self.ssh.run_command("/usr/bin/cat /etc/passwd | egrep -v '^#'")
        if out:
            self.facts['users'] = {}
            for line in out.splitlines():
                user = line.split(':')

                # 0:username 1:password 2:uid 3:gid 4: 5:home-directory 6:shell
                if not user[0] in except_users:
                    profile = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.profile")
                    kshrc = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.kshrc")

                    self.facts['users'][user[0]] = {'uid' : user[2],
                                                    'gid' : user[3],
                                                    'homedir' : user[5],
                                                    'shell' : user[6],
                                                    'profile' : profile + kshrc
                                                   }
    def get_groups(self):
        # List of groups excepted
        except_groups=['root', 'daemon', 'bin', 'sys', 'adm', 'uucp', 'guest', 'nobody', 'lpd',
                      'lp', 'invscout', 'snapp', 'ipsec', 'nuucp', 'sshd', 'ftp', 'anonymou']

        out = self.ssh.run_command("/usr/bin/cat /etc/group | egrep -v '^#'")
        if out:
            self.facts['groups'] = {}
            for line in out.splitlines():
                group = line.split(':')

                # 0:groupname 1: 2:gid 3:users
                if not group[0] in except_groups:
                    self.facts['groups'][group[0]] = {'gid' : group[2],
                                                    'users' : group[3].split(',')
                                                   }

    def get_password_of_users(self):
        tmp_out = self.ssh.run_command(
                  "/usr/bin/cat /etc/security/passwd|egrep ':|password' | sed 's/password = //g' | tr -d '\t '")
        regex = re.compile(r":\n", re.IGNORECASE)
        out = regex.sub(":", tmp_out)
        if out:
            self.facts['shadow'] = {}
            for line in out.splitlines():
                user = line.split(':')
                if user[1] != '*':
                    self.facts['shadow'][user[0]] = user[1]

    def get_ulimits(self):
        tmp_out = self.ssh.run_command("/usr/bin/cat /etc/security/limits | egrep -v '^\*|^$'")
        regex = re.compile(r"\t", re.IGNORECASE)
        out = regex.sub("", tmp_out)

        if out:
            regex = re.compile(r' = ', re.IGNORECASE)

            self.facts['ulimits'] = {}
            for line in out.splitlines():
                if ":" in line:
                    user = line.split(':')
                    self.facts['ulimits'][user[0]] = {}

                if " = " in line:
                    value = line.split(' = ')
                    self.facts['ulimits'][user[0]][value[0]] = value[1]

    def get_crontabs(self):
        out = self.ssh.run_command("/usr/bin/find /var/spool/cron/crontabs -type file")
        if out:
            self.facts['crontabs'] = {}
            for line in out.splitlines():
                out = self.ssh.run_command('/usr/bin/cat ' + line)
                self.facts['crontabs'][line] = out

    def get_default_interfaces(self):
        out = self.ssh.run_command('/usr/bin/netstat -nr')

        self.facts['NICs'] = dict(v4 = {}, v6 = {})

        if out:
            lines = out.splitlines()
            for line in lines:
                words = line.split()
                if len(words) > 1 and words[0] == 'default':
                    if '.' in words[1]:
                        self.facts['NICs']['v4']['gateway'] = words[1]
                        self.facts['NICs']['v4']['interface'] = words[5]
                    elif ':' in words[1]:
                        self.facts['NICs']['v6']['gateway'] = words[1]
                        self.facts['NICs']['v6']['interface'] = words[5]

    # AIX 'ifconfig -a' does not inform about MTU, so remove current_if['mtu'] here
    def parse_interface_line(self, words):
        device = words[0][0:-1]
        current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'type': 'unknown'}
        #current_if['flags'] = self.get_options(words[1])
        current_if['macaddress'] = 'unknown'    # will be overwritten later
        return current_if
    def parse_options_line(self, words, current_if, ips):
        # Mac has options like this...
        current_if['options'] = self.get_options(words[0])

    def parse_nd6_line(self, words, current_if, ips):
        # FreeBSD has options like this...
        current_if['options'] = self.get_options(words[1])

    def parse_ether_line(self, words, current_if, ips):
        current_if['macaddress'] = words[1]

    def parse_media_line(self, words, current_if, ips):
        # not sure if this is useful - we also drop information
        current_if['media'] = words[1]
        if len(words) > 2:
            current_if['media_select'] = words[2]
        if len(words) > 3:
            current_if['media_type'] = words[3][1:]
        if len(words) > 4:
            current_if['media_options'] = self.get_options(words[4])

    def parse_status_line(self, words, current_if, ips):
        current_if['status'] = words[1]

    def parse_lladdr_line(self, words, current_if, ips):
        current_if['lladdr'] = words[1]

    def parse_inet_line(self, words, current_if, ips):
        address = {'address': words[1]}
        # deal with hex netmask
        if re.match('([0-9a-f]){8}', words[3]) and len(words[3]) == 8:
            words[3] = '0x' + words[3]
        if words[3].startswith('0x'):
            address['netmask'] = socket.inet_ntoa(struct.pack('!L', int(words[3], base=16)))
        else:
            # otherwise assume this is a dotted quad
            address['netmask'] = words[3]
        # calculate the network
        address_bin = struct.unpack('!L', socket.inet_aton(address['address']))[0]
        netmask_bin = struct.unpack('!L', socket.inet_aton(address['netmask']))[0]
        address['network'] = socket.inet_ntoa(struct.pack('!L', address_bin & netmask_bin))
        # broadcast may be given or we need to calculate
        if len(words) > 5:
            address['broadcast'] = words[5]
        else:
            address['broadcast'] = socket.inet_ntoa(struct.pack('!L', address_bin | (~netmask_bin & 0xffffffff)))
        # add to our list of addresses
        if not words[1].startswith('127.'):
            ips['all_ipv4_addresses'].append(address['address'])
        current_if['ipv4'].append(address)

    def parse_inet6_line(self, words, current_if, ips):
        address = {'address': words[1]}
        if (len(words) >= 4) and (words[2] == 'prefixlen'):
            address['prefix'] = words[3]
        if (len(words) >= 6) and (words[4] == 'scopeid'):
            address['scope'] = words[5]
        localhost6 = ['::1', '::1/128', 'fe80::1%lo0']
        if address['address'] not in localhost6:
            ips['all_ipv6_addresses'].append(address['address'])
        current_if['ipv6'].append(address)

    def parse_unknown_line(self, words, current_if, ips):
        # we are going to ignore unknown lines here - this may be
        # a bad idea - but you can override it in your subclass
        pass

    def get_interfaces_info(self):
        ifconfig_path = '/etc/ifconfig'
        ifconfig_options='-a'

        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses = [],
            all_ipv6_addresses = [],
        )
        out = self.ssh.run_command('/etc/ifconfig -a')

        for line in out.splitlines():
            if line:
                words = line.split()

                # only this condition differs from GenericBsdIfconfigNetwork
                if re.match('^\w*\d*:', line):
                    current_if = self.parse_interface_line(words)
                    interfaces[ current_if['device'] ] = current_if
                elif words[0].startswith('options='):
                    self.parse_options_line(words, current_if, ips)
                elif words[0] == 'nd6':
                    self.parse_nd6_line(words, current_if, ips)
                elif words[0] == 'ether':
                    self.parse_ether_line(words, current_if, ips)
                elif words[0] == 'media:':
                    self.parse_media_line(words, current_if, ips)
                elif words[0] == 'status:':
                    self.parse_status_line(words, current_if, ips)
                elif words[0] == 'lladdr':
                    self.parse_lladdr_line(words, current_if, ips)
                elif words[0] == 'inet':
                    self.parse_inet_line(words, current_if, ips)
                elif words[0] == 'inet6':
                    self.parse_inet6_line(words, current_if, ips)
                else:
                    self.parse_unknown_line(words, current_if, ips)

        self.facts['interfaces'] = interfaces

    def get_ps_lists(self):
        out = self.ssh.run_command("/usr/bin/ps -ef")


        if out:
            self.facts['processes'] = []

            for line in out.splitlines():
                if "<defunct>" in line: 
                    continue

                data = line.split()
                if data[0] is 'UID':
                    continue

                if re.match('[0-9]:[0-9][0-9]', data[7]):
                    #self.facts['processes'][data[8]] = dict(uid = data[0], cmd = data[8:])
                    self.facts['processes'].append(dict(uid = data[0], cmd = data[8:]))
                elif re.match('[0-9]:[0-9][0-9]', data[6]):
                    #self.facts['processes'][data[7]] = dict(uid = data[0], cmd = data[7:])
                    self.facts['processes'].append(dict(uid = data[0], cmd = data[7:]))

    def get_kernel_parameters(self):
        out = self.ssh.run_command("/usr/sbin/lsattr -E -l sys0")

        if out:
            self.facts['kernel_parameters'] = {}

            for line in out.splitlines():
                data = line.split()

# for main method
def get_args():
    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='RORO Migration executor parser')

    # Source server info
    parser.add_argument('-H', '--host', type=str, help='Source host name or IP', required=True)
    parser.add_argument('-P', '--port', type=str, help='Source host SSH Port', required=False)
    parser.add_argument('-u', '--username', type=str, help='User of Source Server', required=True)
    parser.add_argument('-p', '--password', type=str, help='Password for user', required=True)

    # Array for all arguments passed to script
    args = parser.parse_args()

    return args

def set_params(args):
    params = {}

    params['host'] = args.host
    params['port'] = args.port or 22
    params['username'] = args.username
    params['password'] = args.password

    return params

if __name__ == "__main__":
    args = get_args()

    params = set_params(args)
    print(params)
    aix = AIX(params)
    aix.populate()
    aix.get_results()
