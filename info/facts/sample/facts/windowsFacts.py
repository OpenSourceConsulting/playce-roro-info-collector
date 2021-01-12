# #!/usr/bin/env python2.7
#
# import winrm
#
# import simplejson as json
# import re
# import struct
#
#
# class WINDOWS(object):
#
#   platform = 'WINDOWS'
#
#   def __init__(self, params):
#
#     domain = params.get('host')+":"+params.get('port')
#
#     self.rm = self.create_session(
#         domain, params.get('username'), params.get('password')
#     )
#     self.facts = {}
#
#   def execute(self):
#     try:
#       self.basic_win_info()
#       # self.get_env_vars()
#       # self.get_net_info()
#       # self.get_dns_info()
#       # self.get_route_table()
#       # self.get_drives()
#       # self.get_cpu_facts()
#       # self.get_memory_facts()
#       # self.get_kernel()
#       # self.get_bitmode()
#       # self.get_dmi_facts()
#       # self.get_interfaces_info()
#       # # self.get_vgs_facts()
#       # self.get_users()
#       # self.get_groups()
#       # self.get_password_of_users()
#       # self.get_ulimits()
#       # self.get_crontabs()
#       # self.get_default_interfaces()
#       # self.get_df()
#       # self.get_extra_partitions()
#       # # self.get_ps_lists()
#       # self.get_kernel_parameters()
#       # self.get_timezone()
#       # self.get_firewall()
#       # self.get_listen_port()
#
#     except Exception as err:
#       print str(err)
#
#     finally :
#       return self.facts
#
#   def basic_win_info(self):
#     """
#     Host Name:                 WIN-TB4CSE1DVO7
#     OS Name:                   Microsoft Windows Server 2016 Standard Evaluation
#     OS Version:                10.0.14393 N/A Build 14393
#     OS Manufacturer:           Microsoft Corporation
#     OS Configuration:          Standalone Server
#     OS Build Type:             Multiprocessor Free
#     Registered Owner:          Windows User
#     Registered Organization:
#     Product ID:                00378-00000-00000-AA739
#     Original Install Date:     9/1/2020, 6:14:57 AM
#     System Boot Time:          9/1/2020, 12:27:09 PM
#     System Manufacturer:       innotek GmbH
#     System Model:              VirtualBox
#     System Type:               x64-based PC
#     Processor(s):              1 Processor(s) Installed.
#                                [01]: Intel64 Family 6 Model 142 Stepping 10 GenuineIntel ~2808 Mhz
#     BIOS Version:              innotek GmbH VirtualBox, 12/1/2006
#     Windows Directory:         C:\Windows
#     System Directory:          C:\Windows\system32
#     Boot Device:               \Device\HarddiskVolume1
#     System Locale:             en-us;English (United States)
#     Input Locale:              en-us;English (United States)
#     Time Zone:                 (UTC) Coordinated Universal Time
#     Total Physical Memory:     2,048 MB
#     Available Physical Memory: 1,122 MB
#     Virtual Memory: Max Size:  2,560 MB
#     Virtual Memory: Available: 1,693 MB
#     Virtual Memory: In Use:    867 MB
#     Page File Location(s):     C:\pagefile.sys
#     Domain:                    WORKGROUP
#     Logon Server:              N/A
#     Hotfix(s):                 4 Hotfix(s) Installed.
#                                [01]: KB3192137
#                                [02]: KB3211320
#                                [03]: KB4540723
#                                [04]: KB4540670
#     Network Card(s):           1 NIC(s) Installed.
#                                [01]: Intel(R) PRO/1000 MT Desktop Adapter
#                                      Connection Name: Ethernet
#                                      DHCP Enabled:    Yes
#                                      DHCP Server:     10.0.2.2
#                                      IP address(es)
#                                      [01]: 10.0.2.15
#                                      [02]: fe80::b1f4:7029:c993:7e9c
#     Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
#     :return:
#     """
#     current_if = {}
#     result = self.rm.run_ps('Start-Process "systeminfo" -NoNewWindow -Wait;')
#     if result:
#       self.facts['systeminfo'] = {}
#       for line in result.std_out.splitlines():
#           if line == '' or len(line) < 1:
#             continue
#           data = ' '.join(line.split())
#           result = data.split(":")
#           if line.startswith(' ') == False:
#             if 'Host Name' in line:
#               self.facts['hostname'] = result[1]
#             else:
#               current_if = result[0]
#               self.facts['systeminfo'][result[0]] = result[1]
#           else:
#             if len(result) > 1 and len(result[1]) > 1:
#               self.facts['systeminfo'][current_if] = {result[0] : result[1]}
#
#   def get_env_vars(self):
#     """
#     Key                     Value
#     ---                     -----
#     ALLUSERSPROFILE         C:\ProgramData
#     APPDATA                 C:\Users\Administrator\AppData\Roaming
#     CommonProgramFiles      C:\Program Files\Common Files
#     CommonProgramFiles(x86) C:\Program Files (x86)\Common Files
#     CommonProgramW6432      C:\Program Files\Common Files
#     COMPUTERNAME            WIN-TB4CSE1DVO7
#     ComSpec                 C:\Windows\system32\cmd.exe
#     LOCALAPPDATA            C:\Users\Administrator\AppData\Local
#     NUMBER_OF_PROCESSORS    2
#     OS                      Windows_NT
#     Path                    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShel...
#     PATHEXT                 .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
#     PROCESSOR_ARCHITECTURE  AMD64
#     PROCESSOR_IDENTIFIER    Intel64 Family 6 Model 142 Stepping 10, GenuineIntel
#     PROCESSOR_LEVEL         6
#     PROCESSOR_REVISION      8e0a
#     ProgramData             C:\ProgramData
#     ProgramFiles            C:\Program Files
#     ProgramFiles(x86)       C:\Program Files (x86)
#     ProgramW6432            C:\Program Files
#     PROMPT                  $P$G
#     PSModulePath            C:\Users\Administrator\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShel...
#     PUBLIC                  C:\Users\Public
#     SystemDrive             C:
#     SystemRoot              C:\Windows
#     TEMP                    C:\Users\ADMINI~1\AppData\Local\Temp
#     TMP                     C:\Users\ADMINI~1\AppData\Local\Temp
#     USERDOMAIN              WIN-TB4CSE1DVO7
#     USERNAME                Administrator
#     USERPROFILE             C:\Users\Administrator
#     windir                  C:\Windows
#
#     :return:
#     """
#     result = self.rm.run_ps('Get-ChildItem Env: | ft Key,Value;')
#     cnt = 0;
#     self.facts['env_variables'] = {}
#     # print result.std_out
#     try:
#       for data in result.std_out.splitlines():
#         if cnt < 3:
#           cnt += 1
#           continue
#         if data:
#           pars = re.split(r"\s{2,}", data)
#           self.facts['env_variables'][pars[0]] = pars[1]
#     except Exception as err:
#       print str(err)
#
#
#   def get_net_info(self):
#     """
#     InterfaceAlias InterfaceDescription                 IPv4Address
#     -------------- --------------------                 -----------
#     Ethernet       Intel(R) PRO/1000 MT Desktop Adapter {10.0.2.15}
#     :return:
#     """
#
#     result = self.rm.run_ps('Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address;')
#
#     if result:
#       cnt = 0
#
#       self.facts['interfaces'] = {}
#       for data in result.std_out.splitlines():
#           if cnt < 3:
#               cnt += 1
#               continue
#           result = data.split();
#           self.facts['interfaces'][result[0]] = {
#             'InterfaceDescription' : result[1],
#             'IPv4Address' : result[2]
#           }
#       print result.std_out
#
#   def get_dns_info(self):
#     """
#     InterfaceAlias               Interface Address ServerAddresses
#                              Index     Family
#     --------------               --------- ------- ---------------
#     Ethernet                             6 IPv4    {10.0.2.3}
#     Loopback Pseudo-Interface 1          1 IPv4    {}
#     Teredo Tunneling Pseudo-I...         5 IPv4    {}
#     isatap.{ED78B0B1-1F95-43D...        10 IPv4    {10.0.2.3}
#
#     :return:
#     """
#     result = self.rm.run_ps('Get-DnsClientServerAddress -AddressFamily IPv4 | ft;')
#
#     if result:
#       cnt = 0
#
#       self.facts['dns'] = {}
#       print result.std_out
#       for line in result.std_out.splitlines():
#         if cnt < 3:
#           cnt += 1
#           continue
#
#         if re.match('[^-]', line):
#           data = line.split();
#           self.facts['dns'][data[0]] = {
#             'InterfaceIndex': data[1],
#             'AddressFamily' : data[2],
#             'ServerAddress' : data[3]
#           }
#
#   def create_session(self, domain, username, password):
#     try:
#       return winrm.Session(domain, auth=(username, password))
#     except winrm.FEATURE_OPERATION_TIMEOUT:
#       print('Error: Could not connect to {}.'.format(domain))
#       exit(code=1)
#     except winrm.FEATURE_READ_TIMEOUT:
#       print('Error: Could not connect to {}.'.format(domain))
#       exit(code=1)
#
#   def get_route_table(self):
#     result = self.rm.run_ps('Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex;')
#
#   def get_drives(self):
#     result = self.rm.run_ps('Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"};')
#
#     print result.std_out
#     cnt = 0
#     for line in result.std_out.splitlines():
#       if cnt < 2:
#         cnt += 1
#         continue
#
#       if result:
#         cnt = 0
#
#         self.facts['drives'] = {}
#         for line in result.std_out.splitlines():
#           if cnt < 3:
#             cnt += 1
#             continue
#
#           if re.match('[^-]', line):
#             data = line.split();
#
#             if len(data) == 6 :
#               self.facts['drives'][data[0]] = {
#                 'Used': data[1],
#                 'Free' : data[2],
#                 'Provider' : data[3],
#                 'Root' : data[4],
#                 'CurrentLocation' : data[5]
#               }
