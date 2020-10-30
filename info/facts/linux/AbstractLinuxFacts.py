
import simplejson as json
import abc
from ..ssh.sshBase import *

if sys.version_info >= (3, 4):
  ABC = abc.ABC
else:
  ABC = abc.ABCMeta('ABC', (), {})


class AbstractLinuxFacts(ABC):

  def __init__(self, params, release):
    self.ssh = SshBase()
    self.ssh.connect(params)
    self.facts = {"distribution_version": release}

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

  def get_results(self):
    r = json.dumps(self.facts, indent=2)
    print r
    return r