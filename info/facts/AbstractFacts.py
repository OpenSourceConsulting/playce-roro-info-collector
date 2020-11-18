
import simplejson as json
import abc

from info.facts.log.LogManager import getLogger
from info.facts.ssh.sshBase import *

if sys.version_info >= (3, 4):
  ABC = abc.ABC
else:
  ABC = abc.ABCMeta('ABC', (), {})


class AbstractFacts(ABC):

  def __init__(self, params, isSudo = True):
    self.ssh = SshBase(isSudo=isSudo)
    self.ssh.connect(params)
    self.facts = {};
    self.facts["system_summary"] = dict();
    self.logger = getLogger(params.get('logDir'))

  @abc.abstractmethod
  def get_hostname(self): pass

  @abc.abstractmethod
  def get_cpu_facts(self): pass

  @abc.abstractmethod
  def get_memory_facts(self): pass

  @abc.abstractmethod
  def get_kernel(self): pass

  @abc.abstractmethod
  def get_bitmode(self): pass

  @abc.abstractmethod
  def get_dmi_facts(self): pass

  @abc.abstractmethod
  def get_interfaces_info(self): pass

  @abc.abstractmethod
  def get_vgs_facts(self): pass

  @abc.abstractmethod
  def get_users(self): pass

  @abc.abstractmethod
  def get_groups(self): pass

  @abc.abstractmethod
  def get_password_of_users(self): pass

  @abc.abstractmethod
  def get_ulimits(self): pass

  @abc.abstractmethod
  def get_crontabs(self): pass

  @abc.abstractmethod
  def get_default_interfaces(self): pass

  @abc.abstractmethod
  def get_df(self): pass

  @abc.abstractmethod
  def get_extra_partitions(self): pass

  @abc.abstractmethod
  def get_ps_lists(self): pass

  @abc.abstractmethod
  def get_kernel_parameters(self): pass

  @abc.abstractmethod
  def get_timezone(self): pass

  @abc.abstractmethod
  def get_route_table(self): pass

  @abc.abstractmethod
  def get_firewall(self): pass

  @abc.abstractmethod
  def get_listen_port(self): pass

  @abc.abstractmethod
  def get_locale(self): pass

  @abc.abstractmethod
  def get_env(self): pass

  @abc.abstractmethod
  def get_lvm_info(self): pass

  @abc.abstractmethod
  def get_fs_info(self): pass

  @abc.abstractmethod
  def get_daemon_list(self): pass

  @abc.abstractmethod
  def get_security_info(self): pass

  @abc.abstractmethod
  def get_dns(self): pass

  def get_results(self):
    self.logger.debug("get Result")
    # r = json.dumps(self.facts, indent=2)
    print self.facts
    return self.facts