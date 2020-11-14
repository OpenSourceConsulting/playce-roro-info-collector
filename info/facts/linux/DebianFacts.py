import re
import struct
import socket

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


class DebianFacts(AbstractFacts):

    def __init__(self, params, release):
        AbstractFacts.__init__(self, params)
        self.results = {'distribution_version': release}

    def execute(self):
        try:
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
            # self.get_extra_partitions()
            self.get_ps_lists()
            self.get_kernel_parameters()
            self.get_timezone()
            self.get_route_table()
            self.get_firewall()
            self.get_listen_port()

            self.get_locale()
            self.get_env()
            self.get_fs_info()
            self.get_lvm_info()
            self.get_daemon_list()
            self.get_security_info()
        except Exception as err:
            print str(err)

        finally:
            self.make_system_summary()
            self.facts['results'] = self.results
            return self.results

    def get_distribution_Linux(self):
        """
       Static hostname: roro-ubuntu-1604
             Icon name: computer-vm
               Chassis: vm
            Machine ID: 62dc81efd5858a3e6a42721d5f1a59e6
               Boot ID: 5717741e93f343a78a1e5d2de3a0b56b
        Virtualization: kvm
      Operating System: Ubuntu 16.04.6 LTS
                Kernel: Linux 4.4.0-142-generic
          Architecture: x86-64
    :return:
    """
        out = self.ssh.run_command("hostnamectl")
        for line in out.splitlines():
            data = line.split(":")
            if 'Operating System' in line:
                self.results['distribution_version'] = data[1].strip()
        return self.results['distribution_version'];

    def get_hostname(self):
        out = self.ssh.run_command("uname -n")
        self.results['hostname'] = out.replace('\n', '')

    def get_cpu_facts(self):
        self.results['processor'] = []

        out = self.ssh.run_command("grep 'physical id' /proc/cpuinfo | wc -l")
        self.results['processor_count'] = int(out)

        out = self.ssh.run_command("grep -c processor /proc/cpuinfo")
        self.results['processor_cores'] = int(out)

        """
    model name	: Westmere E56xx/L56xx/X56xx (Nehalem-C)
    """
        out = self.ssh.run_command("grep 'model name' /proc/cpuinfo | tail -1")
        data = out.split(':')[1].strip().replace('\n', '')
        self.results['processor'] = data

    def get_memory_facts(self):
        """
    4044296 K total memory
        67392 K used memory
       365448 K active memory
       128632 K inactive memory
      3447380 K free memory
        34908 K buffer memory
       494616 K swap cache
       998396 K total swap
            0 K used swap
       998396 K free swap
         6912 non-nice user cpu ticks
          830 nice user cpu ticks
         7165 system cpu ticks
     57036338 idle cpu ticks
         4679 IO-wait cpu ticks
            0 IRQ cpu ticks
         1116 softirq cpu ticks
         6436 stolen cpu ticks
       402961 pages paged in
       572728 pages paged out
            0 pages swapped in
            0 pages swapped out
      7790446 interrupts
      9727257 CPU context switches
   1599004765 boot time
         9797 forks
    :return:
    """
        self.results['memory'] = dict(memtotal_mb=None, memfree_mb=None, swaptotal_mb=None, swapfree_mb=None)
        out = self.ssh.run_command("vmstat -s")
        for line in out.splitlines():
            data = line.split()
            if 'total memory' in line:
                memtotal_mb = int(data[0]) // 1024
                self.results['memory']["memtotal_mb"] = memtotal_mb
            if 'free memory' in line:
                memfree_mb = int(data[0]) // 1024
                self.results['memory']["memfree_mb"] = memfree_mb
            if 'total swap' in line:
                swaptotal_mb = int(data[0]) // 1024
                self.results['memory']["swaptotal_mb"] = swaptotal_mb
            if 'free swap' in line:
                swapfree_mb = int(data[0]) // 1024
                self.results['memory']["swapfree_mb"] = swapfree_mb

    def get_kernel(self):
        out = self.ssh.run_command("uname -r")
        self.results['kernal'] = out.replace('\n', '')

    def get_bitmode(self):
        out = self.ssh.run_command("uname -m")
        self.results['architecture'] = out.replace('\n', '')

    def get_df(self):
        """
    Filesystem     Type      Size  Used Avail Use% Mounted on
    udev           devtmpfs  2.0G     0  2.0G   0% /dev
    tmpfs          tmpfs     395M   11M  385M   3% /run
    /dev/sda1      ext4       19G  1.6G   17G   9% /
    tmpfs          tmpfs     2.0G     0  2.0G   0% /dev/shm
    tmpfs          tmpfs     5.0M     0  5.0M   0% /run/lock
    tmpfs          tmpfs     2.0G     0  2.0G   0% /sys/fs/cgroup
    tmpfs          tmpfs     395M     0  395M   0% /run/user/1000
    :return:
    """
        out = self.ssh.run_command("df -Th")

        if out:
            self.results['partitions'] = {}
            regex = re.compile(r'^/dev/', re.IGNORECASE)
            for line in out.splitlines():
                if regex.match(line):
                    pt = line.split()
                    self.results['partitions'][pt[6]] = dict(device=pt[0], fstype=pt[1], size=pt[2], free=pt[4])

    def get_extra_partitions(self):
        """
    FSSTND BSD
    :return:
    """
        root_partitions = ['/', '/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/media', '/mnt', '/proc', '/root',
                           'sbin', '/tmp', '/usr', '/var', '/lost+found']

        # out = self.ssh.run_command("/usr/sbin/lsvg -l rootvg")
        #
        # if out:
        #   self.results['extra_partitions'] = {}
        #   for line in out.splitlines():
        #     data = line.split()
        #     if data[0] in 'rootvg:' or data[0] in 'LV':
        #       continue
        #
        #     self.results['extra_partitions'][data[6]] = \
        #       dict(mount_point = data[0], type=data[1], lv_state = data[5], extra = 'False')
        #
        #     if data[6] not in root_partitions:
        #       self.results['extra_partitions'][data[6]] = \
        #         dict(mount_point = data[0], type=data[1], lv_state = data[5], extra = 'True')

    def get_vgs_facts(self):
        out = self.ssh.run_command("pvs | tail -1")
        if out:
            self.results['vgs'] = {}
            for line in out.splitlines():
                vg = line.split()

                # /dev/sda2  centos lvm2 a--  <99.00g 4.00m
                self.results['vgs'][vg[1]] = {
                    'pv_name': vg[0],
                    'fmt': vg[2],
                    'p_size': vg[4],
                    'p_free': vg[5]
                }

    def get_users(self):
        # List of users excepted
        except_users = []
        out = self.ssh.run_command("cat /etc/passwd | egrep -v '^#'")
        if out:
            self.results['users'] = {}
            for line in out.splitlines():
                user = line.split(':')

                # 0:username 1:password 2:uid 3:gid 4: 5:home-directory 6:shell
                if not user[0] in except_users:
                    profile = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.profile")
                    kshrc = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.kshrc")

                    self.results['users'][user[0]] = {'uid': user[2],
                                                      'gid': user[3],
                                                      'homedir': user[5],
                                                      'shell': user[6],
                                                      'profile': profile + kshrc
                                                      }

    def get_groups(self):
        """
     root:x:0:
     daemon:x:1:
     bin:x:2:
     sys:x:3:
     adm:x:4:syslog,roro
     tty:x:5:
     disk:x:6:
     lp:x:7:
     mail:x:8:
     news:x:9:
     uucp:x:10:
     man:x:12:
     proxy:x:13:
     kmem:x:15:
     dialout:x:20:
     fax:x:21:
     voice:x:22:
     cdrom:x:24:roro
     floppy:x:25:
     tape:x:26:
     sudo:x:27:roro
     audio:x:29:
     dip:x:30:roro
     www-data:x:33:
     backup:x:34:
     operator:x:37:
     list:x:38:
     irc:x:39:
     src:x:40:
     gnats:x:41:
     shadow:x:42:
    """
        # List of groups excepted
        except_groups = []

        out = self.ssh.run_command("cat /etc/group | egrep -v '^#'")
        if out:
            self.results['groups'] = {}
            for line in out.splitlines():
                group = line.split(':')

                # 0:groupname 1: 2:gid 3:users
                if not group[0] in except_groups:
                    self.results['groups'][group[0]] = {'gid': group[2],
                                                        'users': group[3].split(',')
                                                        }

    def get_password_of_users(self):
        out = self.ssh.run_command("cat /etc/shadow")
        if out:
            self.results['shadow'] = {}
            for line in out.splitlines():
                user = line.split(':')
                if user[1] != '*' and user[1] != '!':
                    self.results['shadow'][user[0]] = user[1]

    def get_ulimits(self):
        """
        core file size          (blocks, -c) 0
        data seg size           (kbytes, -d) unlimited
        scheduling priority             (-e) 0
        file size               (blocks, -f) unlimited
        pending signals                 (-i) 15633
        max locked memory       (kbytes, -l) 64
        max memory size         (kbytes, -m) unlimited
        open files                      (-n) 1024
        pipe size            (512 bytes, -p) 8
        POSIX message queues     (bytes, -q) 819200
        real-time priority              (-r) 0
        stack size              (kbytes, -s) 8192
        cpu time               (seconds, -t) unlimited
        max user processes              (-u) 15633
        virtual memory          (kbytes, -v) unlimited
        file locks                      (-x) unlimited
        """
        user_list = self.ssh.run_command("cut -f1 -d: /etc/passwd")

        self.results['ulimits'] = {}
        for user in user_list.splitlines():
            try:

                command = ("su - %s --shell /bin/bash -c 'ulimit -a'") % user
                tmp_out = self.ssh.run_command(command)
                regex = re.compile(r"\t", re.IGNORECASE)
                out = regex.sub("", tmp_out)

                if out:
                    self.results['ulimits'][user] = {}
                    for line in out.splitlines():
                        key = line[0:line.index("(")].strip()
                        value = line[line.index("("):len(line)].split()
                        self.results['ulimits'][user][key] = value[len(value) - 1]
            except self.ssh.ShellError:
                print("Dump command executing error!!")

    def get_crontabs(self):

        out = self.ssh.run_command("find /var/spool/cron  -type f")
        if out:
            self.results['crontabs'] = {}
            for line in out.splitlines():
                out = self.ssh.run_command('cat ' + line)
                self.results['crontabs'][line] = out

        out = self.ssh.run_command("find /var/spool/cron/crontabs  -type f")
        if out:
            self.results['crontabs'] = {}
            for line in out.splitlines():
                out = self.ssh.run_command('cat ' + line)
                self.results['crontabs'][line] = out

    def get_default_interfaces(self):
        out = self.ssh.run_command('netstat -ern')

        self.results['NICs'] = dict(v4={}, v6={})

        if out:
            lines = out.splitlines()
            for line in lines:
                words = line.split()
                if len(words) > 1 and words[0] == '0.0.0.0':
                    if '.' in words[1]:
                        self.results['NICs']['v4']['gateway'] = words[1]
                        self.results['NICs']['v4']['interface'] = words[7]
                    elif ':' in words[1]:
                        self.results['NICs']['v6']['gateway'] = words[1]
                        self.results['NICs']['v6']['interface'] = words[7]

    def get_interfaces_info(self):
        """
    ens3      Link encap:Ethernet  HWaddr 56:6f:30:d5:00:82
          inet addr:192.168.0.151  Bcast:192.168.255.255  Mask:255.255.0.0
          inet6 addr: fe80::546f:30ff:fed5:82/64 Scope:Link
          inet6 addr: fd0c:b572:ca6c:0:546f:30ff:fed5:82/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1702011 errors:0 dropped:36 overruns:0 frame:0
          TX packets:15752 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:209853896 (209.8 MB)  TX bytes:2437673 (2.4 MB)

    lo        Link encap:Local Loopback
              inet addr:127.0.0.1  Mask:255.0.0.0
              inet6 addr: ::1/128 Scope:Host
              UP LOOPBACK RUNNING  MTU:65536  Metric:1
              RX packets:160 errors:0 dropped:0 overruns:0 frame:0
              TX packets:160 errors:0 dropped:0 overruns:0 carrier:0
              collisions:0 txqueuelen:1
              RX bytes:11840 (11.8 KB)  TX bytes:11840 (11.8 KB)
    """
        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses=[],
            all_ipv6_addresses=[],
        )

        out = self.ssh.run_command("ifconfig -a")
        for line in out.splitlines():
            if line:
                words = line.split()

                # only this condition differs from GenericBsdIfconfigNetwork
                # centos 6 difference
                if 'Link encap' in line:
                    current_if = self.parse_interface_line(words)
                    interfaces[current_if['device']] = current_if
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

    def parse_interface_line(self, words):
        device = words[0][0:-1]
        current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'type': 'unknown'}
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
        for idx, word in enumerate(words):
            if ':' in word:
                words[idx] = word[word.index(':') + 1:]
        address = {'address': words[1]}
        # deal with hex netmask
        if re.match('([0-9a-f]){8}', words[len(words) - 1]) and len(words[len(words) - 1]) == 8:
            words[len(words) - 1] = '0x' + words[len(words) - 1]
        if words[len(words) - 1].startswith('0x'):
            address['netmask'] = socket.inet_ntoa(struct.pack('!L', int(words[len(words) - 1], base=16)))
        else:
            # otherwise assume this is a dotted quad
            address['netmask'] = words[len(words) - 1]
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

        address = {'address': words[2]}
        # if (len(words) >= 4) and (words[2] == 'prefixlen'):
        #   address['prefix'] = words[3]
        # if (len(words) >= 6) and (words[4] == 'scopeid'):
        #   address['scope'] = words[5]
        if 'Scope:' in words[3]:
            address['scope'] = words[3][words[3].index(':') + 1:]
        localhost6 = ['::1', '::1/128', 'fe80::1%lo0']
        if address['address'] not in localhost6:
            ips['all_ipv6_addresses'].append(address['address'])
        current_if['ipv6'].append(address)

    def parse_unknown_line(self, words, current_if, ips):
        # we are going to ignore unknown lines here - this may be
        # a bad idea - but you can override it in your subclass
        pass

    def get_ps_lists(self):
        out = self.ssh.run_command("ps -ef")

        if out:
            self.results['processes'] = {}

            for line in out.splitlines():
                if "<defunct>" in line:
                    continue

                if 'UID' in line:
                    continue

                data = line.split()

                if re.match('[0-9][0-9]:[0-9][0-9]:[0-9][0-9]', data[7]):
                    self.results['processes'][data[7]] = dict(uid=data[0], cmd=data[8:])
                    # self.results['processes'].append(dict(uid = data[0], cmd = data[8:]))
                elif re.match('[0-9][0-9]:[0-9][0-9]:[0-9][0-9]', data[6]):
                    self.results['processes'][data[7]] = dict(uid=data[0], cmd=data[7:])
                    # self.results['processes'].append(dict(uid = data[0], cmd = data[7:]))

    def get_kernel_parameters(self):
        out = self.ssh.run_command("sysctl -a")

        self.results['kernel_parameters'] = {}
        for line in out.splitlines():
            data = line.split('=')
            self.results['kernel_parameters'][data[0].strip()] = data[1].strip()

    def get_dmi_facts(self):
        """
    Getting SMBIOS data from sysfs.
    SMBIOS 2.8 present.
    13 structures occupying 790 bytes.
    Table at 0xBFFFFCE0.

    Handle 0x0000, DMI type 0, 24 bytes
    BIOS Information
      Vendor: SeaBIOS
      Version: 1.11.0-2.el7
      Release Date: 04/01/2014
      Address: 0xE8000
      Runtime Size: 96 kB
      ROM Size: 64 kB
      Characteristics:
        BIOS characteristics not supported
        Targeted content distribution is supported
      BIOS Revision: 0.0

    Handle 0x0100, DMI type 1, 27 bytes
    System Information
      Manufacturer: oVirt
      Product Name: oVirt Node
      Version: 7-8.2003.0.el7.centos
      Serial Number: 39333835-3636-4753-4830-333758564644
      UUID: F65BB4F0-F5A5-4DFA-B4E6-1DFFB3C80488
      Wake-up Type: Power Switch
      SKU Number: Not Specified
      Family: Red Hat Enterprise Linux

    Handle 0x0300, DMI type 3, 21 bytes
    Chassis Information
      Manufacturer: Red Hat
      Type: Other
      Lock: Not Present
      Version: RHEL 7.6.0 PC (i440FX + PIIX, 1996)
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Boot-up State: Safe
      Power Supply State: Safe
      Thermal State: Safe
      Security Status: Unknown
      OEM Information: 0x00000000
      Height: Unspecified
      Number Of Power Cords: Unspecified
      Contained Elements: 0

    Handle 0x0400, DMI type 4, 42 bytes
    Processor Information
      Socket Designation: CPU 0
      Type: Central Processor
      Family: Other
      Manufacturer: Red Hat
      ID: C1 06 02 00 FF FB 8B 07
      Version: RHEL 7.6.0 PC (i440FX + PIIX, 1996)
      Voltage: Unknown
      External Clock: Unknown
      Max Speed: 2000 MHz
      Current Speed: 2000 MHz
      Status: Populated, Enabled
      Upgrade: Other
      L1 Cache Handle: Not Provided
      L2 Cache Handle: Not Provided
      L3 Cache Handle: Not Provided
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Part Number: Not Specified
      Core Count: 1
      Core Enabled: 1
      Thread Count: 1
      Characteristics: None

    Handle 0x0401, DMI type 4, 42 bytes
    Processor Information
      Socket Designation: CPU 1
      Type: Central Processor
      Family: Other
      Manufacturer: Red Hat
      ID: C1 06 02 00 FF FB 8B 07
      Version: RHEL 7.6.0 PC (i440FX + PIIX, 1996)
      Voltage: Unknown
      External Clock: Unknown
      Max Speed: 2000 MHz
      Current Speed: 2000 MHz
      Status: Populated, Enabled
      Upgrade: Other
      L1 Cache Handle: Not Provided
      L2 Cache Handle: Not Provided
      L3 Cache Handle: Not Provided
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Part Number: Not Specified
      Core Count: 1
      Core Enabled: 1
      Thread Count: 1
      Characteristics: None

    Handle 0x0402, DMI type 4, 42 bytes
    Processor Information
      Socket Designation: CPU 2
      Type: Central Processor
      Family: Other
      Manufacturer: Red Hat
      ID: C1 06 02 00 FF FB 8B 07
      Version: RHEL 7.6.0 PC (i440FX + PIIX, 1996)
      Voltage: Unknown
      External Clock: Unknown
      Max Speed: 2000 MHz
      Current Speed: 2000 MHz
      Status: Populated, Enabled
      Upgrade: Other
      L1 Cache Handle: Not Provided
      L2 Cache Handle: Not Provided
      L3 Cache Handle: Not Provided
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Part Number: Not Specified
      Core Count: 1
      Core Enabled: 1
      Thread Count: 1
      Characteristics: None

    Handle 0x0403, DMI type 4, 42 bytes
    Processor Information
      Socket Designation: CPU 3
      Type: Central Processor
      Family: Other
      Manufacturer: Red Hat
      ID: C1 06 02 00 FF FB 8B 07
      Version: RHEL 7.6.0 PC (i440FX + PIIX, 1996)
      Voltage: Unknown
      External Clock: Unknown
      Max Speed: 2000 MHz
      Current Speed: 2000 MHz
      Status: Populated, Enabled
      Upgrade: Other
      L1 Cache Handle: Not Provided
      L2 Cache Handle: Not Provided
      L3 Cache Handle: Not Provided
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Part Number: Not Specified
      Core Count: 1
      Core Enabled: 1
      Thread Count: 1
      Characteristics: None

    Handle 0x1000, DMI type 16, 23 bytes
    Physical Memory Array
      Location: Other
      Use: System Memory
      Error Correction Type: Multi-bit ECC
      Maximum Capacity: 4 GB
      Error Information Handle: Not Provided
      Number Of Devices: 1

    Handle 0x1100, DMI type 17, 40 bytes
    Memory Device
      Array Handle: 0x1000
      Error Information Handle: Not Provided
      Total Width: Unknown
      Data Width: Unknown
      Size: 4096 MB
      Form Factor: DIMM
      Set: None
      Locator: DIMM 0
      Bank Locator: Not Specified
      Type: RAM
      Type Detail: Other
      Speed: Unknown
      Manufacturer: Red Hat
      Serial Number: Not Specified
      Asset Tag: Not Specified
      Part Number: Not Specified
      Rank: Unknown
      Configured Clock Speed: Unknown
      Minimum Voltage: Unknown
      Maximum Voltage: Unknown
      Configured Voltage: Unknown

    Handle 0x1300, DMI type 19, 31 bytes
    Memory Array Mapped Address
      Starting Address: 0x00000000000
      Ending Address: 0x000BFFFFFFF
      Range Size: 3 GB
      Physical Array Handle: 0x1000
      Partition Width: 1

    Handle 0x1301, DMI type 19, 31 bytes
    Memory Array Mapped Address
      Starting Address: 0x00100000000
      Ending Address: 0x0013FFFFFFF
      Range Size: 1 GB
      Physical Array Handle: 0x1000
      Partition Width: 1

    Handle 0x2000, DMI type 32, 11 bytes
    System Boot Information
      Status: No errors detected

    Handle 0x7F00, DMI type 127, 4 bytes
    End Of Table
    :return:
    """
        out = self.ssh.run_command("dmidecode -s bios-version")
        self.results['firmware_version'] = out.replace('\n', '')

        out = self.ssh.run_command("dmidecode -s system-serial-number")
        self.results['product_serial'] = out.replace('\n', '')

        out = self.ssh.run_command("dmidecode -s processor-manufacturer")
        self.results['product_name'] = out.replace('\n', '')

    def get_timezone(self):
        """
      Time zone: Asia/Seoul (KST, +0900)
    :return:
    """
        out = self.ssh.run_command("timedatectl | grep 'Time zone'")
        self.results['timezone'] = out.split(':')[1].strip().replace('\n', '')

    def get_route_table(self):
        out = self.ssh.run_command("netstat -rn |  tail -n+3")

        if out:
            self.results['route_table'] = []
            # Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
            for line in out.splitlines():
                data = line.split()
                self.results['route_table'].append({
                    'destination' : data[0],
                    'gateway' : data[1],
                    'genmask' : data[2],
                    'flags' : data[3],
                    'mss' : data[4],
                    'window' : data[5],
                    'irtt' : data[6],
                    'iface' : data[7],
                })

    def get_listen_port(self):
        """
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
    tcp6       0      0 :::22                   :::*                    LISTEN      -
    udp        0      0 0.0.0.0:68              0.0.0.0:*
    :return:
    """
        out = self.ssh.run_command("netstat -tunlp")

        if out:
            self.results['listen_port_list'] = {}

            for line in out.splitlines():
                if '(only servers)' in line:
                    continue

                if "Proto" in line:
                    continue

                data = line.split()

                if not self.results['listen_port_list'].get(data[0]):
                    self.results['listen_port_list'][data[0]] = {}

                if 'LISTEN' in line:
                    self.results['listen_port_list'][data[0]][data[6]] = {
                        "localAddress": data[3],
                        "foreignAddress": data[4],
                        "state": data[5],
                    }
                else:
                    self.results['listen_port_list'][data[0]][data[5]] = {
                        "localAddress": data[3],
                        "foreignAddress": data[4],
                        "state": '',
                    }

    def get_firewall(self):
        """
    Chain INPUT (policy ACCEPT)
    num  target     prot opt source               destination
    1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:21
    2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8000
    3    DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8000
    4    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    5    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080

    Chain OUTPUT (policy ACCEPT)
    num  target     prot opt source               destination
    1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:21

    Chain FORWARD (policy ACCEPT)
    num  target     prot opt source               destination
    1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080

    Chain PREROUTING (policy ACCEPT)
    num  target     prot opt source               destination
    1    DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:192.168.0.3
    2    DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:192.168.0.4

    Chain INPUT (policy ACCEPT)
    num  target     prot opt source               destination

    Chain OUTPUT (policy ACCEPT)
    num  target     prot opt source               destination

    Chain POSTROUTING (policy ACCEPT)
    num  target     prot opt source               destination
    1    SNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:192.168.0.2
    2    SNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:192.168.0.2
    :return:
    """
        chain_type = ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']

        commands = [
            'iptables -L --line-number -n',
            'iptables -t nat -L --line-number -n'
        ]

        self.results['firewall'] = {}

        for cmd in commands:
            out = self.ssh.run_command(cmd)
            if out:
                curent_chain = {}
                type = ''

                for line in out.splitlines():
                    if 'num' in line or len(line) < 1:
                        continue

                    if 'INPUT' in line:
                        type = 'input'
                        curent_chain[type] = {}
                    elif 'OUTPUT' in line:
                        type = 'output'
                        curent_chain[type] = {}
                    elif 'FORWARD' in line:
                        type = 'forward'
                        curent_chain[type] = {}
                    elif 'PREROUTING' in line:
                        type = 'prerouting'
                        curent_chain[type] = {}
                    elif 'POSTROUTING' in line:
                        type = 'postrouting'
                        curent_chain[type] = {}
                    else:
                        self.parse_chain_rule(curent_chain, line, type)

            if 'nat' in cmd:
                self.results['firewall']['extra_rules'] = curent_chain
            else:
                self.results['firewall']['rules'] = curent_chain

    def parse_chain_rule(self, cur_chain, line, type):

        line = re.sub('\s+', '\t', line)
        data = line.split()
        part1 = data[0:5]
        part2 = data[5:len(data)]
        info = {
            'target': part1[1],
            'protocol': part1[2],
            'source': part1[4],
            'destination': ','.join(part2)
        }

        cur_chain[type][data[0]] = info

    def get_locale(self):
        locale = self.ssh.run_command("locale")

        if locale:
            self.results['locale'] = dict()

            for line in locale.splitlines():
                key, value = line.split("=")
                self.results['locale'][key] = value

    def get_env(self):
        env = self.ssh.run_command("env")

        if env:
            self.results['env'] = dict()

            for line in env.splitlines():
                key, value = line.split("=")
                self.results['env'][key] = value

    def get_lvm_info(self):
        vgs = self.ssh.run_command("vgs | awk '{print $1}' | tail -n+2")

        if vgs:
            self.results['vgs'] = {}
            for vg in vgs.splitlines():
                self.results['vgs'][vg] = dict(pvs=[], lvs=[])

        lvs = self.ssh.run_command("lvdisplay")

        if lvs:
            for line in lvs.splitlines():
                line = line.strip()
                if re.match('(-+\s\w+\s\w+\s+-+)', line):
                    lv_info = {}
                if 'LV Path' in line:
                    value = line.replace("LV Path", "").strip()
                    lv_info.update({"lv_path": value})
                elif 'LV Name' in line:
                    value = line.replace("LV Name", "").strip()
                    lv_info.update({"lv_name": value})
                elif 'VG Name' in line:
                    value = line.replace("VG Name", "").strip()
                    lv_info.update({"vg_name": value})
                    self.results['vgs'][value]['lvs'].append(lv_info)
                elif 'LV UUID' in line:
                    value = line.replace("LV UUID", "").strip()
                    lv_info.update({"lv_uuid": value})
                elif 'LV Size' in line:
                    value = line.replace("LV Size", "").strip()
                    lv_info.update({"lv_size": value})
                # elif 'LV Write Access' in line:
                # elif 'Current LE' in line:
                # elif 'Block device' in line:
                # elif 'LV Creation host, time' in line:

        pvs = self.ssh.run_command("pvdisplay")

        if pvs:
            for line in pvs.splitlines():
                line = line.strip()
                if re.match('(-+\s\w+\s\w+\s+-+)', line):
                    pv_info = {}
                elif 'PV Name' in line:
                    value = line.replace("PV Name", "").strip()
                    pv_info.update({"pv_name": value})
                elif 'VG Name' in line:
                    value = line.replace("VG Name", "").strip()
                    pv_info.update({"vg_name": value})
                    self.results['vgs'][value]['pvs'].append(pv_info)
                elif 'PV Size' in line:
                    value = line.replace("PV Size", "").strip()
                    pv_info.update({"pv_size": value})
                elif 'Allocatable' in line:
                    value = line.replace("Allocatable", "").strip()
                    pv_info.update({"allocatable": value})
                elif 'PE Size' in line:
                    value = line.replace("PE Size", "").strip()
                    pv_info.update({"pe_size": value})
                elif 'Total PE' in line:
                    value = line.replace("Total PE", "").strip()
                    pv_info.update({"total_pe": value})
                elif 'Free PE' in line:
                    value = line.replace("Free PE", "").strip()
                    pv_info.update({"free_pe": value})
                elif 'Allocated PE' in line:
                    value = line.replace("Allocated PE", "").strip()
                    pv_info.update({"allocated_pe": value})
                elif 'PV UUID' in line:
                    value = line.replace("PV UUID", "").strip()
                    pv_info.update({"pv_uuid": value})

    def get_fs_info(self):
        None

    def get_fstab_info(self):
        fstab = self.ssh.run_command("cat /etc/fstab")

        if fstab:
            self.results['fstab'] = []
            regex = re.compile('^\#')
            for line in fstab.splitlines():
                if regex.match(line) or line in ['', '\n']:
                    continue
                info = line.split()

                self.results['fstab'].append(
                    dict(device=info[0], mount=info[1], type=info[2], option=info[4], dump=info[5])
                )
    def get_daemon_list(self):
        out = self.ssh.run_command("service --status-all")

        if out:
            self.results['daemon_list'] = {}
            for m in re.finditer('(\[+\s+\S+\s+\])+\s+(\S+)', out):

                if '+' in m.group(1):
                    self.results['daemon_list'][m.group(2)] = "running"
                elif '-' in m.group(1):
                    self.results['daemon_list'][m.group(2)] = "stop"
                else:
                    self.results['daemon_list'][m.group(2)] = "unknown"

    def get_security_info(self):
        out = self.ssh.run_command("cat /etc/login.defs")

        if out:
            self.results['security'] = {"password": dict()}
            for line in out.splitlines():

                regex = re.compile('^\#')
                if regex.match(line) or line in ['', '\n']:
                    continue

                key, value = line.split()
                self.results['security']["password"][key] = value

    def get_dns(self):
        out = self.ssh.run_command("cat /etc/resolv.conf")

        if out:
            self.results['dns'] = []
            for line in out.splitlines():

                regex = re.compile('^\#')
                if regex.match(line) or line in ['', '\n']:
                    continue

                data = line.split()
                self.results['dns'].append(data[1])

    def make_system_summary(self):
        self.facts["system_summary"]["os"] = self.results['distribution_version']
        self.facts["system_summary"]["hostname"] = self.results['hostname']

        self.facts["system_summary"]["processor_count"] = self.results['processor_count']
        self.facts["system_summary"]["cores"] = self.results['processor_cores']
        self.facts["system_summary"]["cpu"] = self.results['processor']

        self.facts["system_summary"]["memory"] = self.results['memory']["memtotal_mb"]
        self.facts["system_summary"]["swap"] = self.results['memory']["swaptotal_mb"]

        self.facts["system_summary"]["kernel"] = self.results['kernel']
        self.facts["system_summary"]["architecture"] = self.results['architecture']
        self.facts["system_summary"]["firmware_version"] = self.results['firmware_version']
        self.facts["system_summary"]["product_serial"] = self.results['product_serial']
        # self.facts["system_summary"]["lpar_info"] = self.results['lpar_info']
        self.facts["system_summary"]["vendor"] = self.results['product_name']

        self.facts["system_summary"]["disk_info"] = self.results['partitions']

        self.facts['system_summary']['network_info'] = self.results['interfaces']
