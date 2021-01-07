#!/usr/bin/env python2.7
import re
import socket
import struct
from info.facts.log.LogManager import LogManager
from info.facts.AbstractFacts import AbstractFacts

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


class AixFacts(AbstractFacts):

    def __init__(self, params, release):
        AbstractFacts.__init__(self, params, isSudo=False)
        self.results = {"family": "aix"}

    def execute(self):
        try:
            # self.get_distribution_AIX()
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
            # self.get_default_interfaces()
            self.get_df()
            self.get_extra_partitions()
            self.get_ps_lists()
            self.get_kernel_parameters()
            self.get_route_table()
            self.get_listen_port()
            self.get_locale()
            self.get_env()
            self.get_fs_info()
            self.get_lvm_info()
            self.get_daemon_list()
            self.get_dns()
            self.get_security_info()
            self.get_timezone()
            self.get_firewall()
            self.get_login_def()
        except Exception as err:
            LogManager.logger.error(err)

        finally:
            # self.make_system_summary()
            self.facts["results"] = self.results
            return self.results

    @LogManager.logging
    def get_distribution_AIX(self):
        out = self.ssh.run_command("/usr/bin/uname -a")
        data = out.split('.')
        self.results['distribution_version'] = data[0]
        self.results['distribution_release'] = data[1]

    @LogManager.logging
    def get_hostname(self):
        out = self.ssh.run_command("/usr/bin/hostname")
        self.results['hostname'] = out.replace('\n', '')

    @LogManager.logging
    def get_cpu_facts(self):
        self.results['processor'] = []

        out = self.ssh.run_command("/usr/sbin/lsdev -Cc processor")
        if out:
            i = 0
            for line in out.splitlines():
                if 'Available' in line:
                    if i == 0:
                        data = line.split(' ')
                        cpudev = data[0]
                    i += 1

            self.results['processor_count'] = int(i)

            out = self.ssh.run_command("/usr/sbin/lsattr -El " + cpudev + " -a type")

            data = out.split(' ')
            self.results['processor'] = data[1]

            out = self.ssh.run_command(
                "/usr/sbin/lsattr -El " + cpudev + " -a smt_threads")

            data = out.split(' ')
            self.results['processor_cores'] = int(data[1])

    @LogManager.logging
    def get_memory_facts(self):
        pagesize = 4096
        out = self.ssh.run_command("/usr/bin/vmstat -v")
        for line in out.splitlines():
            data = line.split()
            if 'memory pages' in line:
                pagecount = int(data[0])
            if 'free pages' in line:
                freecount = int(data[0])
        memtotal_mb = pagesize * pagecount // 1024 // 1024
        memfree_mb = pagesize * freecount // 1024 // 1024

        self.results['memory'] = dict(memtotal_mb=memtotal_mb, memfree_mb=memfree_mb)
        # self.results['memory']["memtotal_mb"] = memtotal_mb
        # self.results['memory']["memfree_mb"] = memfree_mb
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
            swapfree_mb = int(swaptotal_mb * (100 - percused) / 100)
            self.results['memory']['swaptotal_mb'] = swaptotal_mb
            self.results['memory']['swapfree_mb'] = swapfree_mb

    @LogManager.logging
    def get_kernel(self):
        out = self.ssh.run_command("lslpp -l | grep bos.mp")

        lines = out.splitlines()
        data = lines[0].split()

        self.results['kernel'] = data[1]

    @LogManager.logging
    def get_bitmode(self):
        out = self.ssh.run_command("getconf KERNEL_BITMODE")
        self.results['architecture'] = out.replace('\n', '')

    @LogManager.logging
    def get_dmi_facts(self):
        out = self.ssh.run_command("/usr/sbin/lsattr -El sys0 -a fwversion")
        data = out.split()
        self.results['firmware_version'] = data[1].strip('IBM,')

        out = self.ssh.run_command("/usr/sbin/lsconf")
        if out:
            for line in out.splitlines():
                data = line.split(':')
                if 'Machine Serial Number' in line:
                    self.results['product_serial'] = data[1].strip()
                if 'LPAR Info' in line:
                    self.results['lpar_info'] = data[1].strip()
                if 'System Model' in line:
                    self.results['product_name'] = data[1].strip()

    @LogManager.logging
    def get_df(self):
        out = self.ssh.run_command("/usr/bin/df -m")

        if out:
            self.results['partitions'] = {}
            regex = re.compile(r'^/dev/', re.IGNORECASE)
            for line in out.splitlines():
                if regex.match(line):
                    pt = line.split()
                    self.results['partitions'][pt[6]] = dict(device=pt[0],
                                                             fstype=self.get_fs_type(
                                                                 pt[0]), size=pt[1],
                                                             free=pt[2])

    @LogManager.logging
    def get_fs_type(self, device):
        short_device_name = device.split('/')[2]

        cmd = "/usr/sbin/lsvg -l rootvg"
        out = self.ssh.run_command(cmd)

        for line in out.splitlines():
            if re.match(("^%s" % short_device_name), line):
                return line.split()[1]

    @LogManager.logging
    def get_extra_partitions(self):
        root_partitions = ['N/A', '/', '/usr', '/var', '/tmp', '/home', '/proc',
                           '/opt', '/admin', '/var/adm/ras/livedump']

        out = self.ssh.run_command("/usr/sbin/lsvg -l rootvg")

        if out:
            self.results['extra_partitions'] = {}
            for line in out.splitlines():
                data = line.split()
                if data[0] in 'rootvg:' or data[0] in 'LV':
                    continue

                partInfo = dict(mount_point=data[0], type=data[1], lv_state=data[5], extra='False')
                if data[6] not in self.results['extra_partitions']:
                    self.results['extra_partitions'][data[6]] = []
                    self.results['extra_partitions'][data[6]].append(partInfo)
                else:
                    if data[6] not in root_partitions:
                        self.results['extra_partitions'][data[6]].append(
                            dict(mount_point=data[0], type=data[1], lv_state=data[5],
                                 extra='True'))
                    else:
                        self.results['extra_partitions'][data[6]].append(partInfo)

    @LogManager.logging
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
        cmd = "%s | %s %s -p" % (lsvg_path, xargs_path, lsvg_path)
        if lsvg_path and xargs_path:
            out = self.ssh.run_command(cmd)
            if out:
                self.results['vgs'] = {}
                for m in re.finditer(
                        r'(\S+):\n.*FREE DISTRIBUTION(\n(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*)+',
                        out):
                    self.results['vgs'][m.group(1)] = []
                    pp_size = 0
                    cmd = "%s %s" % (lsvg_path, m.group(1))
                    out = self.ssh.run_command(cmd)
                    if out:
                        pp_size = re.search(r'PP SIZE:\s+(\d+\s+\S+)', out).group(1)
                        for n in re.finditer(r'(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*',
                                             m.group(0)):
                            pv_info = {'pv_name': n.group(1),
                                       'pv_state': n.group(2),
                                       'total_pps': n.group(3),
                                       'free_pps': n.group(4),
                                       'pp_size': pp_size
                                       }
                            self.results['vgs'][m.group(1)].append(pv_info)

    @LogManager.logging
    def get_users(self):
        # List of users excepted
        except_users = ['daemon', 'bin', 'sys', 'adm', 'uucp', 'guest', 'nobody',
                        'lpd',
                        'lp', 'invscout', 'snapp', 'ipsec', 'nuucp', 'sshd', 'ftp',
                        'anonymou']

        out = self.ssh.run_command("/usr/bin/cat /etc/passwd | egrep -v '^#'")
        if out:
            self.results['users'] = {}
            for line in out.splitlines():
                user = line.split(':')

                # 0:username 1:password 2:uid 3:gid 4: 5:home-directory 6:shell
                if not user[0] in except_users:
                    profile = self.ssh.run_command(
                        "/usr/bin/cat " + user[5] + "/.profile")
                    kshrc = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.kshrc")

                    self.results['users'][user[0]] = {'uid': user[2],
                                                      'gid': user[3],
                                                      'homedir': user[5],
                                                      'shell': user[6],
                                                      'profile': profile + kshrc
                                                      }

    @LogManager.logging
    def get_groups(self):
        # List of groups excepted
        except_groups = ['root', 'daemon', 'bin', 'sys', 'adm', 'uucp', 'guest',
                         'nobody', 'lpd',
                         'lp', 'invscout', 'snapp', 'ipsec', 'nuucp', 'sshd', 'ftp',
                         'anonymou']

        out = self.ssh.run_command("/usr/bin/cat /etc/group | egrep -v '^#'")
        if out:
            self.results['groups'] = {}
            for line in out.splitlines():
                group = line.split(':')

                # 0:groupname 1: 2:gid 3:users
                if not group[0] in except_groups:
                    self.results['groups'][group[0]] = {'gid': group[2],
                                                        'users': group[3].split(',')
                                                        }

    @LogManager.logging
    def get_password_of_users(self):
        tmp_out = self.ssh.run_command(
            "/usr/bin/cat /etc/security/passwd|egrep ':|password' | sed 's/password = //g' | tr -d '\t '")
        regex = re.compile(r":\n", re.IGNORECASE)
        out = regex.sub(":", tmp_out)
        if out:
            self.results['shadow'] = {}
            for line in out.splitlines():
                user = line.split(':')
                if user[1] != '*':
                    self.results['shadow'][user[0]] = user[1]

    @LogManager.logging
    def get_ulimits(self):
        tmp_out = self.ssh.run_command(
            "/usr/bin/cat /etc/security/limits | egrep -v '^\*|^$'")
        regex = re.compile(r"\t", re.IGNORECASE)
        out = regex.sub("", tmp_out)

        if out:
            regex = re.compile(r' = ', re.IGNORECASE)

            self.results['ulimits'] = {}
            for line in out.splitlines():
                if ":" in line:
                    user = line.split(':')
                    self.results['ulimits'][user[0]] = {}

                if " = " in line:
                    value = line.split(' = ')
                    self.results['ulimits'][user[0]][value[0]] = value[1]

    @LogManager.logging
    def get_crontabs(self):
        out = self.ssh.run_command(
            "/usr/bin/find /var/spool/cron/crontabs -type file")
        if out:
            self.results['crontabs'] = {}
            for line in out.splitlines():
                out = self.ssh.run_command('/usr/bin/cat ' + line)
                self.results['crontabs'][line] = out

    @LogManager.logging
    def get_default_interfaces(self):
        out = self.ssh.run_command('/usr/bin/netstat -nr')

        self.results['NICs'] = dict(v4={}, v6={})

        if out:
            lines = out.splitlines()
            for line in lines:
                words = line.split()
                if len(words) > 1 and words[0] == 'default':
                    if '.' in words[1]:
                        self.results['NICs']['v4']['gateway'] = words[1]
                        self.results['NICs']['v4']['interface'] = words[5]
                    elif ':' in words[1]:
                        self.results['NICs']['v6']['gateway'] = words[1]
                        self.results['NICs']['v6']['interface'] = words[5]

    # AIX 'ifconfig -a' does not inform about MTU, so remove current_if['mtu'] here
    def parse_interface_line(self, words):
        device = words[0][0:-1]
        current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'gateway': 'unknown'}
        # current_if['flags'] = self.get_options(words[1])
        current_if['macaddress'] = 'unknown'  # will be overwritten later
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
            address['netmask'] = socket.inet_ntoa(
                struct.pack('!L', int(words[3], base=16)))
        else:
            # otherwise assume this is a dotted quad
            address['netmask'] = words[3]
        # calculate the network
        address_bin = struct.unpack('!L', socket.inet_aton(address['address']))[0]
        netmask_bin = struct.unpack('!L', socket.inet_aton(address['netmask']))[0]
        address['network'] = socket.inet_ntoa(
            struct.pack('!L', address_bin & netmask_bin))
        # broadcast may be given or we need to calculate
        if len(words) > 5:
            address['broadcast'] = words[5]
        else:
            address['broadcast'] = socket.inet_ntoa(
                struct.pack('!L', address_bin | (~netmask_bin & 0xffffffff)))

        # out = self.ssh.run_command('/usr/bin/netstat -nr')
        #
        # if out:
        #   lines = out.splitlines()
        #   for line in lines:
        #     words = line.split()
        #     if len(words) > 1 and words[0] == 'default' and words[5] == current_if['device']:
        #       if '.' in words[1]:
        #         address['gateway'] = words[1]
        #       elif ':' in words[1]:
        #         address['gateway'] = words[1]

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
        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses=[],
            all_ipv6_addresses=[],
        )
        out = self.ssh.run_command('/etc/ifconfig -a')

        for line in out.splitlines():
            if line:
                words = line.split()

                # only this condition differs from GenericBsdIfconfigNetwork
                if re.match('^\w*\d*:', line):
                    current_if = self.parse_interface_line(words)
                    interfaces[current_if['device']] = current_if
                    current_if['gateway'] = self.get_default_gateway(current_if)
                    current_if['macaddress'] = self.get_mac_address(current_if)
                    # current_if['type'] = self.get_interface_type(current_if)
                    # current_if['script'] = self.get_ifcfg_script(current_if)
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

        self.results['interfaces'] = interfaces

    @LogManager.logging
    def get_ps_lists(self):
        out = self.ssh.run_command("/usr/bin/ps -ef")

        if out:
            self.results['processes'] = {}

            for line in out.splitlines():
                if "<defunct>" in line:
                    continue

                data = line.split()
                if data[0] is 'UID':
                    continue

                #  UID     PID    PPID   C    STIME    TTY  TIME CMD
                if re.match('[0-9]:[0-9][0-9]', data[7]):
                    self.results['processes'][data[8]] = dict(uid=data[0], pid=data[1], cmd=data[8:])
                elif re.match('[0-9]:[0-9][0-9]', data[6]):
                    if re.match('\[(.*?)\]', data[7]):
                        continue
                    self.results['processes'][data[7]] = dict(uid=data[0], pid=data[1], cmd=data[7:])

    @LogManager.logging
    def get_kernel_parameters(self):
        out = self.ssh.run_command("/usr/sbin/lsattr -E -l sys0")

        if out:
            self.results['kernel_parameters'] = {}

            for line in out.splitlines():
                data = line.split()
                # self.results['kernel_parameters'][data[0]] = {
                #   "value": data[1],
                #   "description": " ".join(data[2:-1]),
                #   "changable": data[-1]
                # }
                self.results['kernel_parameters'][data[0]] = data[1]
                # self.results['kernel_parameters'][data[0].strip()] = data[1].strip()

    @LogManager.logging
    def get_timezone(self):
        out = self.ssh.run_command(
            "/usr/bin/env | grep TZ | awk -F '=' '{print $2}'")
        if out:
            self.results['timezone'] = re.sub(r'\n', '', out)

    @LogManager.logging
    def get_route_table(self):
        out = self.ssh.run_command("/usr/bin/netstat -rn")

        self.results['route_table'] = []

        dd = out.split('\n\n')
        for idx, data in enumerate(dd):
            for info in data.splitlines():
                words = info.split()
                if idx < 1 or words[0] == 'Route':
                    continue

                info = {
                    "destination": words[0],
                    "gateway": words[1],
                    # "Flags" : words[2],
                    "iface": words[5],
                }

                self.results['route_table'].append(info)

    @LogManager.logging
    def get_listen_port(self):

        self.results['port_list'] = {
            'listen': [],
            'established': {}
        }

        out = self.ssh.run_command("/usr/bin/netstat -Aan | grep LISTEN")
        if out:
            listen_port = []
            self.results['port_list']['listen'] = listen_port
            for line in out.splitlines():
                data = line.split()

                l_addr, l_port = data[4].rsplit('.', 1)
                f_addr, f_port = data[5].rsplit('.', 1)

                port_info = {
                    "protocol": data[1],
                    "bind_addr": l_addr,
                    "port": l_port,
                }

                user_info = self.ssh.run_command(("/usr/sbin/rmsock %s tcpcb") % data[0])
                usage_info = re.split(r'\s+proccess\s', user_info)

                if len(usage_info) > 1:
                    pid, pname = usage_info[1].split()
                    pname = re.sub('[\(\)\.]', '', str(pname))
                    port_info['pid'] = pid
                    port_info['name'] = pname
                else:
                    port_info['pid'] = "-"
                    port_info['name'] = "-"

                listen_port.append(port_info)

        out = self.ssh.run_command("/usr/bin/netstat -Aan | grep ESTABLISHED")
        if out:
            any_to_local = []
            local_to_any = []
            estab_port = {
                'any_to_local': any_to_local,
                'local_to_any': local_to_any
            }
            self.results['port_list']['established'] = estab_port
            for line in out.splitlines():

                data = line.split()

                l_addr, l_port = data[4].rsplit('.', 1)
                f_addr, f_port = data[5].rsplit('.', 1)

                if l_addr == '127.0.0.1' and f_addr == '127.0.0.1':
                    continue

                port_info = {
                    "protocol": data[1],
                    "faddr": f_addr,
                    "fport": f_port,
                    "laddr": l_addr,
                    "lport": l_port,
                }

                user_info = self.ssh.run_command(("/usr/sbin/rmsock %s tcpcb") % data[0])

                usage_info = re.split(r'\s+proccess\s', user_info)

                if len(usage_info) > 1:
                    pid, pname = usage_info[1].split()
                    pname = re.sub('[\(\)\.]', '', str(pname))
                    port_info['pid'] = pid
                    port_info['name'] = pname
                else:
                    port_info['pid'] = "-"
                    port_info['name'] = "-"

                if next((lport for lport in listen_port if lport['port'] == l_port), None):
                    any_to_local.append(port_info)
                else:
                    local_to_any.append(port_info)

    @LogManager.logging
    def get_locale(self):
        locale = self.ssh.run_command("locale")

        if locale:
            self.results['locale'] = dict()

            for line in locale.splitlines():
                key, value = line.split("=")
                self.results['locale'][key] = re.sub('"', '', value)

    @LogManager.logging
    def get_env(self):
        env = self.ssh.run_command("env")

        if env:
            self.results['env'] = dict()

            for line in env.splitlines():
                key, value = line.split("=")
                self.results['env'][key] = value

    @LogManager.logging
    def get_lvm_info(self):
        lsvg_path = "/usr/sbin/lsvg"
        xargs_path = "/usr/bin/xargs"
        cmd = "%s | %s %s -p" % (lsvg_path, xargs_path, lsvg_path)
        if lsvg_path and xargs_path:
            out = self.ssh.run_command(cmd)
            if out:
                self.results['vgs'] = {}
                for m in re.finditer(
                        r'(\S+):\n.*FREE DISTRIBUTION(\n(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*)+',
                        out):
                    self.results['vgs'][m.group(1)] = dict(pvs=[], lvs=[])
                    pp_size = 0
                    cmd = "%s %s" % (lsvg_path, m.group(1))
                    out = self.ssh.run_command(cmd)
                    if out:
                        pp_size = re.search(r'PP SIZE:\s+(\d+\s+\S+)', out).group(1)
                        for n in re.finditer(r'(\S+)\s+(\w+)\s+(\d+)\s+(\d+).*',
                                             m.group(0)):
                            pv_info = {'pv_name': n.group(1),
                                       'pv_state': n.group(2),
                                       'total_pps': n.group(3),
                                       'free_pps': n.group(4),
                                       'pp_size': pp_size
                                       }
                            self.results['vgs'][m.group(1)]['pvs'].append(pv_info)

                    cmd = "%s -l %s" % (lsvg_path, m.group(1))
                    out = self.ssh.run_command(cmd)

                    if out:
                        for line in out.splitlines():
                            if m.group(1) in line or 'LV NAME' in line:
                                continue

                            data = line.split()
                            lv_info = {'lv_name': data[0],
                                       'lv_type': data[1],
                                       'lps': data[2],
                                       'pps': data[3],
                                       'pvs': data[4],
                                       'lv_state': data[5],
                                       'mount_point': data[6]
                                       }
                            self.results['vgs'][m.group(1)]['lvs'].append(lv_info)

    @LogManager.logging
    def get_fs_info(self):
        fsList = self.ssh.run_command("/usr/bin/cat /etc/filesystems")

        if fsList:
            self.results['file_system'] = dict()

            for line in fsList.splitlines():

                regex = re.compile('^\*')
                if regex.match(line):
                    continue

                if ":" in line:
                    fs = line.split(":")[0]
                    self.results['file_system'][fs] = {}

                if "=" in line:
                    line = re.sub(r"[\t|\"]", '', line)
                    key, value = line.rsplit("=")
                    self.results['file_system'][fs][key.strip()] = value.strip()

    @LogManager.logging
    def get_daemon_list(self):
        daemonList = self.ssh.run_command("/usr/bin/lssrc -a")

        if daemonList:
            self.results['daemon_list'] = []

            for line in daemonList.splitlines():

                if 'PID' in line:
                    continue

                data = line.split()

                daemon = dict(name=data[0], group=None, pid=None, status=None)

                if len(data) == 3:
                    if re.match('\d', data[1]):
                        daemon.update({
                            'group': '',
                            'pid': data[1],
                            'status': data[2]
                        })
                    else:
                        daemon.update({
                            'group': data[1],
                            'pid': '',
                            'status': data[2]
                        })
                elif len(data) == 2:
                    daemon.update({
                        'group': '',
                        'pid': '',
                        'status': data[1]
                    })
                else:
                    daemon.update({
                        'group': data[1],
                        'pid': data[2],
                        'status': data[3]
                    })

                self.results['daemon_list'].append(daemon)

    @LogManager.logging
    def get_security_info(self):
        self.results['security'] = {}

        # Login policies
        out = self.ssh.run_command("cat /etc/security/login.cfg")
        if out:
            login = {}
            self.results['security']['login'] = login
            for line in out.splitlines():

                regex = re.compile('^\*')
                if regex.match(line) or line in ['', '\n']:
                    continue

                if ':' in line:
                    user = line.replace(":", "")
                    current_if = {}
                    login[user] = current_if
                else:
                    key, value = line.split("=")
                    current_if.update({
                        re.sub('\t', '', key): value.lstrip()
                    })

        # Password policies
        out = self.ssh.run_command("cat /etc/security/user")
        if out:
            password = {}
            self.results['security']['password'] = password
            for line in out.splitlines():

                regex = re.compile('^\*')
                if regex.match(line) or line in ['', '\n']:
                    continue

                if ':' in line:
                    user = line.replace(":", "")
                    current_if = {}
                    password[user] = current_if
                else:
                    key, value = line.split("=")
                    current_if.update({
                        re.sub('\t', '', key): value.lstrip()
                    })

    @LogManager.logging
    def get_firewall(self):
        None

    @LogManager.logging
    def get_dns(self):
        out = self.ssh.run_command("cat /etc/resolv.conf")
        self.results['dns'] = []
        if out:
            for line in out.splitlines():

                regex = re.compile('^\#')
                if regex.match(line) or line in ['', '\n']:
                    continue

                data = line.split()
                for ns in data[1:]:
                    self.results['dns'].append(ns)

    @LogManager.logging
    def get_login_def(self):
        self.results['def_info'] = dict(uid_min=201, uid_max=60000, gid_min=201, gid_max=60000)

    def get_default_gateway(self, current_if):
        out = self.ssh.run_command('netstat -rn | grep default')

        if out:
            lines = out.splitlines()
            for line in lines:
                words = line.split()
                if len(words) > 1 and words[0] == 'default':
                    if words[5] == current_if['device']:
                        return words[1]

    def get_mac_address(self, current_if):
        out = self.ssh.run_command('entstat -d ' + current_if['device'] + ' | egrep Hardware')

        if out:
            data = out.split(":", 1)
            return data[1].strip().replace(r'\n', '')

    def get_interface_type(self, current_if):
        out = self.ssh.run_command('entstat -d ' + current_if['device'] + ' | egrep Device')

        if out:
            data = out.split(":", 1)
            return data[1].strip().replace(r'\n', '')

    def make_system_summary(self):
        self.facts["system_summary"]["os"] = self.results['distribution_version']
        self.facts["system_summary"]["hostname"] = self.results['hostname']
        self.facts["system_summary"]["family"] = self.results['family']

        self.facts["system_summary"]["kernel"] = self.results['kernel']
        self.facts["system_summary"]["architecture"] = self.results['architecture']
        self.facts["system_summary"]["vendor"] = self.results['product_name']
        self.facts["system_summary"]["defInfo"] = self.results['def_info']

        self.make_cpu_summary()
        self.make_memory_summary()
        self.make_disk_summary()
        self.make_network_summary()

    def make_cpu_summary(self):
        self.facts["system_summary"]["cores"] = self.results['processor_cores']
        self.facts["system_summary"]["cpu"] = self.results['processor']

    def make_memory_summary(self):
        self.facts["system_summary"]["memory"] = self.results['memory']["memtotal_mb"]
        self.facts["system_summary"]["swap"] = self.results['memory']["swaptotal_mb"]

    def make_disk_summary(self):
        self.facts["system_summary"]["diskInfo"] = self.results['partitions']

    def make_network_summary(self):
        self.facts['system_summary']['networkInfo'] = dict(interfaces=self.results['interfaces'])
        self.facts['system_summary']['networkInfo']['dns'] = self.results['dns']