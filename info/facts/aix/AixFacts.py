#!/usr/bin/env python2.7

import re
import socket
import struct

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

  def __init__(self, params):
    AbstractFacts.__init__(self, params, "AIX", isSudo=False)
    self.results = {}

  def execute(self):
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
      self.get_kernel_parameters()
      self.get_timezone()
      self.get_route_table()
      # self.get_firewall()
      self.get_listen_port()
      self.get_locale()
      self.get_env()
      self.get_fs_info()
      self.get_lvm_info()
    except Exception as err:
      print str(err)

    finally:
      self.system_summary = self.get_system_summary();
      self.facts["results"] = self.results
      return self.results

  def get_distribution_AIX(self):
    out = self.ssh.run_command("/usr/bin/oslevel")
    data = out.split('.')
    self.results['distribution_version'] = data[0]
    self.results['distribution_release'] = data[1]

    self.facts["system_summary"]["os"] = "AIX "+data[0]+"."+data[1]

  def get_hostname(self):
    out = self.ssh.run_command("/usr/bin/hostname")
    self.results['hostname'] = out.replace('\n', '')
    self.facts["system_summary"]["hostname"] = self.results['hostname']

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

      self.facts["system_summary"]["processor_count"] = self.results[
        'processor_count']
      self.facts["system_summary"]["cores"] = self.results[
        'processor_cores']
      self.facts["system_summary"]["cpu"] = self.results['processor']

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

    self.facts["system_summary"]["memory"] = memtotal_mb

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
      self.facts["system_summary"]["swap"] = swaptotal_mb
      self.results['memory']['swaptotal_mb'] = swaptotal_mb
      self.results['memory']['swapfree_mb'] = swapfree_mb

  def get_kernel(self):
    out = self.ssh.run_command("lslpp -l | grep bos.mp")

    lines = out.splitlines()
    data = lines[0].split()

    self.results['kernel'] = data[1]
    self.facts["system_summary"]["kernel"] = self.results['kernel']

  def get_bitmode(self):
    out = self.ssh.run_command("getconf KERNEL_BITMODE")
    self.results['architecture'] = out.replace('\n', '')
    self.facts["system_summary"]["architecture"] = self.results['architecture']+"-bit"

  def get_dmi_facts(self):
    out = self.ssh.run_command("/usr/sbin/lsattr -El sys0 -a fwversion")
    data = out.split()
    self.results['firmware_version'] = data[1].strip('IBM,')
    self.facts["system_summary"]["firmware_version"] = self.results[
      'firmware_version']

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

      self.facts["system_summary"]["product_serial"] = self.results[
        'product_serial']
      self.facts["system_summary"]["lpar_info"] = self.results['lpar_info']
      self.facts["system_summary"]["vendor"] = self.results[
        'product_name']

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
          self.facts["system_summary"]["disk_info"] = self.results['partitions']

  def get_fs_type(self, device):
    short_device_name = device.split('/')[2]

    cmd = "/usr/sbin/lsvg -l rootvg"
    out = self.ssh.run_command(cmd)

    for line in out.splitlines():
      if re.match(("^%s" % short_device_name), line):
        return line.split()[1]

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

        self.results['extra_partitions'][data[6]] = \
          dict(mount_point=data[0], type=data[1], lv_state=data[5],
               extra='False')

        if data[6] not in root_partitions:
          self.results['extra_partitions'][data[6]] = \
            dict(mount_point=data[0], type=data[1], lv_state=data[5],
                 extra='True')

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

  def get_crontabs(self):
    out = self.ssh.run_command(
      "/usr/bin/find /var/spool/cron/crontabs -type file")
    if out:
      self.results['crontabs'] = {}
      for line in out.splitlines():
        out = self.ssh.run_command('/usr/bin/cat ' + line)
        self.results['crontabs'][line] = out

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
    self.facts['system_summary']['network_info'] = interfaces

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


        if re.match('[0-9]:[0-9][0-9]', data[7]):
            self.results['processes'][data[8]] = dict(uid = data[0], cmd = data[8:])
        elif re.match('[0-9]:[0-9][0-9]', data[6]):
            self.results['processes'][data[7]] = dict(uid = data[0], cmd = data[7:])

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

  def get_timezone(self):
    out = self.ssh.run_command(
      "/usr/bin/env | grep TZ | awk -F '=' '{print $2}'")
    if out:
      self.results['timezone'] = out

  def get_route_table(self):
    out = self.ssh.run_command("/usr/bin/netstat -rn")

    self.results['route_table'] = dict(list=[])

    dd = out.split('\n\n')
    for idx, data in enumerate(dd):
      for info in data.splitlines():
        words = info.split()
        if idx < 1 or words[0] == 'Route':
          continue

        info = {
          "destination": words[0],
          "Gateway": words[1],
          # "Flags" : words[2],
          "Iface": words[5],
        }

        self.results['route_table']['list'].append(info)

  def get_listen_port(self):
    ps_list = self.ssh.run_command("/usr/bin/netstat -Aan | grep LISTEN")

    if ps_list:
      self.results['listen_port_list'] = {}

      for line in ps_list.splitlines():

        data = line.split()

        if not self.results['listen_port_list'].get(data[1]):
          self.results['listen_port_list'][data[1]] = dict()

        local_addr, l_port = data[4].rsplit('.', 1)
        frg_addr, f_port = data[5].rsplit('.', 1)

        command = ("/usr/sbin/rmsock %s tcpcb") % data[0]
        user_info = self.ssh.run_command(command)

        usage_info = re.split(r'\s+proccess\s', user_info)

        if len(usage_info) > 1:
          pid, user = usage_info[1].split()
          user = re.sub('[\(\)\.]', '', str(user))

          port_info = {
            "localAddress": local_addr,
            "foreignAddress": frg_addr,
            "fPort": f_port,
            "state": data[6],
            "user": user,
            "pid": pid,
            "fd": data[0]
          }
          self.results['listen_port_list'][data[1]][l_port] = []
          self.results['listen_port_list'][data[1]][l_port].append(port_info)
        else:
          None
          # print "get_listen_port, Error, %s file descriptor parsing" % data[0]

  def get_locale(self):
    locale = self.ssh.run_command("locale")

    if locale:
      self.results['locale'] = dict()

      for line in locale.splitlines():
          key, value = line.split("=")
          self.results['locale'][key]=value

  def get_env(self):
    env = self.ssh.run_command("env")

    if env:
      self.results['env'] = dict()

      for line in env.splitlines():
        key, value = line.split("=")
        self.results['env'][key]=value

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
          self.results['vgs'][m.group(1)] = dict(pvs=[],lvs=[])
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
           key, value = line.split("=")
           self.results['file_system'][fs][key]=value

  def get_deamon_list(self):
      None

  def get_security_info(self):
      None

  def get_firewall(self):
    None


  def get_system_summary(self):
      None