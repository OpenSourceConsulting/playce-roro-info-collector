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

class RhelFacts(AbstractFacts):

  def __init__(self, params, release):
    AbstractFacts.__init__(self, params, release)
    self.results = {}

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


    except Exception as err:
      print str(err)

    finally :
      self.facts['results'] = self.results
      return self.results

  def get_hostname(self):
    out = self.ssh.run_command("uname -n")
    self.results['hostname'] = out.replace('\n','')

  def check_path_exist(self, path):
    f_template = self.CHECK_FILE_EXIT
    out = self.ssh.run_command(f_template.replace('PATH',path))

    if out == 'Y':
      return True
    else :
      d_template = self.CHECK_DIR_EXIT
      out = self.ssh.run_command(d_template.replace('PATH',path))
      if out == 'Y':
        return True;
      else:
        return False;


  def get_cpu_facts(self):
    self.results['processor'] = []

    out = self.ssh.run_command("grep 'physical id' /proc/cpuinfo | wc -l")
    self.results['processor_count'] = int(out)

    out = self.ssh.run_command("grep -c processor /proc/cpuinfo")
    self.results['processor_cores'] = int(out)

    out = self.ssh.run_command("grep 'model name' /proc/cpuinfo | tail -1")
    data = out.split(':')[1].strip().replace('\n','')
    self.results['processor'] = data

    self.facts["system_summary"]["processor_count"] = self.results['processor_count']
    self.facts["system_summary"]["processor_cores"] = self.results['processor_cores']
    self.facts["system_summary"]["processor"] = data


  def get_memory_facts(self):
    self.results['memory'] = dict(memtotal_mb=None, memfree_mb=None, swaptotal_mb=None, swapfree_mb=None)
    out = self.ssh.run_command("vmstat -s")
    for line in out.splitlines():
      data = line.split()
      if 'total memory' in line:
        memtotal_mb = int(data[0]) // 1024
        self.facts["system_summary"]["memtotal_mb"] = memtotal_mb
        self.results['memory']["memtotal_mb"] = memtotal_mb
      if 'free memory' in line:
        memfree_mb = int(data[0]) // 1024
        self.facts["system_summary"]["memfree_mb"] = memfree_mb
        self.results['memory']["memfree_mb"] = memfree_mb
      if 'total swap' in line:
        swaptotal_mb = int(data[0]) // 1024
        self.facts["system_summary"]["swaptotal_mb"] = swaptotal_mb
        self.results['memory']["swaptotal_mb"] = swaptotal_mb
      if 'free swap' in line:
        swapfree_mb = int(data[0]) // 1024
        self.facts["system_summary"]["swapfree_mb"] = swapfree_mb
        self.results['memory']["swapfree_mb"] = swapfree_mb

  def get_kernel(self):
    out = self.ssh.run_command("uname -r")
    self.results['kernal'] = out.replace('\n','')
    self.facts["system_summary"]["kernal"] = out.replace('\n','')

  def get_bitmode(self):
    out = self.ssh.run_command("uname -m")
    self.results['architecture'] = out.replace('\n','')
    self.facts["system_summary"]["architecture"] = out.replace('\n','')

  def get_df(self):
    out = self.ssh.run_command("df -Th")

    if out:
      self.results['partitions'] = {}
      regex = re.compile(r'^/dev/', re.IGNORECASE)
      for line in out.splitlines():
        if regex.match(line):
          pt = line.split()
          self.results['partitions'][pt[6]] = dict(device = pt[0], fstype = pt[1], size = pt[2], free = pt[4])


  def get_extra_partitions(self):
    root_partitions = ['N/A', '/', '/usr', '/var', '/tmp', '/home', '/proc', '/opt', '/admin', '/var/adm/ras/livedump']

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
          'pv_name' : vg[0],
          'fmt' : vg[2],
          'p_size' : vg[4],
          'p_free' : vg[5]
        }

  def get_users(self):
    # List of users excepted
    except_users=[]
    out = self.ssh.run_command("cat /etc/passwd | egrep -v '^#'")
    if out:
      self.results['users'] = {}
      for line in out.splitlines():
        user = line.split(':')

        # 0:username 1:password 2:uid 3:gid 4: 5:home-directory 6:shell
        if not user[0] in except_users:
          profile = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.profile")
          kshrc = self.ssh.run_command("/usr/bin/cat " + user[5] + "/.kshrc")

          self.results['users'][user[0]] = {'uid' : user[2],
                                          'gid' : user[3],
                                          'homedir' : user[5],
                                          'shell' : user[6],
                                          'profile' : profile + kshrc
                                          }
  def get_groups(self):
    # List of groups excepted
    except_groups=[]

    out = self.ssh.run_command("cat /etc/group | egrep -v '^#'")
    if out:
      self.results['groups'] = {}
      for line in out.splitlines():
        group = line.split(':')

        # 0:groupname 1: 2:gid 3:users
        if not group[0] in except_groups:
          self.results['groups'][group[0]] = {'gid' : group[2],
                                            'users' : group[3].split(',')
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
            self.results['ulimits'][user][key] = value[len(value)-1]
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
    out = self.ssh.run_command('ip route')

    self.results['NICs'] = dict(v4 = [], v6 = [])

    if out:
      lines = out.splitlines()
      for line in lines:
        words = line.split()
        if len(words) > 1 and words[0] == 'default':
          if '.' in words[2]:
            cur_info = {'gateway' : words[2],'interface' : words[words.index("dev")+1] }
            self.results['NICs']['v4'].append(cur_info)
          elif ':' in words[2]:
            self.results['NICs']['v6']['gateway'] = words[2]
            self.results['NICs']['v6']['interface'] = words[line.index("dev")+1]

  def get_interfaces_info(self):
    interfaces = {}
    current_if = {}
    ips = dict(
        all_ipv4_addresses = [],
        all_ipv6_addresses = [],
    )

    """
      Red Hat - ifconfig -a deprecate (ip addr)
    """
    out = self.ssh.run_command("ip addr")
    for line in out.splitlines():
      if line:
        words = line.split()

        # only this condition differs from GenericBsdIfconfigNetwork
        # centos 6 difference
        if re.match('^\d*:', line):
          current_if = self.parse_interface_line(words)
          interfaces[ current_if['device'] ] = current_if
        # elif words[0].startswith('options='):
        #   self.parse_options_line(words, current_if, ips)
        # elif words[0] == 'nd6':
        #   self.parse_nd6_line(words, current_if, ips)
        # elif words[0] == 'ether':
        #   self.parse_ether_line(words, current_if, ips)
        # elif words[0] == 'media:':
        #   self.parse_media_line(words, current_if, ips)
        # elif words[0] == 'status:':
        #   self.parse_status_line(words, current_if, ips)
        # elif words[0] == 'lladdr':
        #   self.parse_lladdr_line(words, current_if, ips)
        elif words[0] == 'inet':
          self.parse_inet_line(words, current_if, ips)
        elif words[0] == 'inet6':
          self.parse_inet6_line(words, current_if, ips)
        else:
          self.parse_unknown_line(words, current_if, ips)

    self.results['interfaces'] = interfaces

  def parse_interface_line(self, words):
    device = words[1][0:-1]
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
    # deal with hex netmask
    s_addr, s_net_bits = words[1].split('/')
    address = {'address': s_addr}

    address['netmask'] = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << 32 - int(s_net_bits))))

    # calculate the network
    address_bin = struct.unpack('!L', socket.inet_aton(address['address']))[0]
    netmask_bin = struct.unpack('!L', socket.inet_aton(address['netmask']))[0]
    # broadcast may be given or we need to calculate
    address['broadcast'] = socket.inet_ntoa(struct.pack('!L', address_bin | (~netmask_bin & 0xffffffff)))
    # add to our list of addresses
    if not words[1].startswith('127.'):
      ips['all_ipv4_addresses'].append(address['address'])
    current_if['ipv4'].append(address)

  def parse_inet6_line(self, words, current_if, ips):
    s_addr, s_net_bits = words[1].split('/')
    address = {'address': s_addr}
    address['prefix'] = s_net_bits
    address['scope'] = words[3]
    # if (len(words) >= 4) and (words[2] == 'prefixlen'):
    #   address['prefix'] = words[3]
    # if (len(words) >= 6) and (words[4] == 'scopeid'):
    #   address['scope'] = words[5]
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
          self.results['processes'][data[7]] = dict(uid = data[0], cmd = data[8:])
          # self.results['processes'].append(dict(uid = data[0], cmd = data[8:]))
        elif re.match('[0-9][0-9]:[0-9][0-9]:[0-9][0-9]', data[6]):
          self.results['processes'][data[7]] = dict(uid = data[0], cmd = data[7:])
          # self.results['processes'].append(dict(uid = data[0], cmd = data[7:]))

  def get_kernel_parameters(self):
    out = self.ssh.run_command("sysctl -a")

    self.results['kernel_parameters'] = {}
    for line in out.splitlines():
      data = line.split('=')
      self.results['kernel_parameters'][data[0].strip()] = data[1].strip()


  def get_dmi_facts(self):
    out = self.ssh.run_command("dmidecode -s bios-version")
    self.results['firmware_version'] = out.replace('\n','')

    out = self.ssh.run_command("dmidecode -s system-serial-number")
    self.results['product_serial'] =out.replace('\n','')

    out = self.ssh.run_command("dmidecode -s processor-manufacturer")
    self.results['product_name'] = ''.join(sorted(set(out), key=out.index))

    self.facts["system_summary"]["firmware_version"] = self.results['firmware_version']
    self.facts["system_summary"]["product_serial"] = self.results['product_serial']
    self.facts["system_summary"]["product_name"] = self.results['product_name']


  def get_timezone(self):
    out = self.ssh.run_command("timedatectl | grep 'Time zone'")
    self.results['timezone'] =out.split(':')[1].strip().replace('\n','')
    self.facts["system_summary"]["timezone"] = self.results['timezone']

  def get_route_table(self):
    out = self.ssh.run_command("ip route")
    self.results['route_table'] = dict(list=[])
    for line in out.splitlines():
      data = line.split()

      info = {
        "destination" : data[0],
        "Iface" : data[data.index("dev")+1]
      }

      if 'via' in line:
        info["Gateway"] = data[data.index("via")+1]
      else:
        info["Gateway"] = '0.0.0.0'

      # if 'proto' in line:
      #   info["Protocol"] = data[data.index("proto")+1]
      # else:
      #   info["Protocol"] = ''
      # if 'metric' in line:
      #   info["Metric"] = data[data.index("metric")+1]
      # else:
      #   info["Metric"] = ''
      #
      # if 'scope' in line:
      #   info["Scope"] = data[data.index("scope")+1]
      # else:
      #   info["Scope"] = ''
      #
      # if 'src' in line:
      #   info["Src"] = data[data.index("src")+1]
      # else:
      #   info["Src"] = ''

      self.results['route_table']['list'].append(info)

  def get_listen_port(self):
    out = self.ssh.run_command("ss -nutlp | grep LISTEN")

    if out:
      self.results['listen_port_list'] = {}

      for line in out.splitlines():
        data = line.split()

        if not self.results['listen_port_list'].get(data[0]):
          self.results['listen_port_list'][data[0]] = dict()

        local_addr, l_port = data[4].rsplit(':', 1)
        frg_addr, f_port = data[5].rsplit(':', 1)

        regex = re.compile(r'users:\(\(|\)\)|pid=|fd=|\"', re.IGNORECASE)
        userInfos = regex.sub("", data[6])

        for info in re.split(r"\),\(",userInfos):
          user, pid, fd = info.split(",")

          port_info = {
            "localAddress" : local_addr,
            "foreignAddress" : frg_addr,
            "fPort" : f_port,
            "state" : data[1],
            "user" : user,
            "pid" : pid,
            "fd" : fd
          }

          self.results['listen_port_list'][data[0]][l_port] = []
          self.results['listen_port_list'][data[0]][l_port].append(port_info)

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
          if 'Chain' in line:
            data = line.split();
            type = data[1]
            curent_chain[type] = {}
            continue

          if 'num' in line or len(line) < 1:
            continue

          self.parse_chain_rule(curent_chain, line, type)

      if 'nat' in cmd:
        self.results['firewall']['extra_rules'] = curent_chain
      else:
        self.results['firewall']['rules'] = curent_chain



  def parse_chain_rule(self, cur_chain, line, type):

    line = re.sub('\s+','\t',line)
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
