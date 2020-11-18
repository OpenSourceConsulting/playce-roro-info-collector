# -*- coding: utf-8 -*-
#!/usr/bin/python

import argparse

from facts.linux.LinuxFactorGenerator import *
from facts.aix.AixFacts import *
from info.facts.sample.facts.windowsFacts import *

def get_args():
  '''This function parses and return arguments passed in'''
  # Assign description to the help doc
  parser = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter,
      description='RORO Migration executor parser')

  # Source server info
  parser.add_argument('-H', '--host', type=str, help='Source host name or IP', required=True)
  parser.add_argument('-P', '--port', type=str, help='Source host SSH Port', required=True)
  parser.add_argument('-u', '--username', type=str, help='User of Source Server', required=True)
  parser.add_argument('-p', '--password', type=str, help='Password for user', required=True)
  parser.add_argument('-T', '--target', type=str, help='target os', required=True)
  parser.add_argument('-L', '--log_dir', type=str, help='log directory path', required=False)

  # Array for all arguments passed to script
  args = parser.parse_args()

  return args

def set_params(args):
  params = {}

  params['host'] = args.host
  params['port'] = args.port or 22
  params['username'] = args.username
  params['password'] = args.password
  params['target'] = args.target
  params['logDir'] = args.log_dir

  return params


def main(params):

  if params['target'] == 'linux':
    module = LinuxFactorGenerator(params)
    module.get_info()
  elif params['target'] == 'unix':
    module = AixFacts(params);
    module.execute()
  elif params['target'] == 'windows':
    module = WINDOWS(params)
    module.execute()

  module.get_results()



if __name__ == "__main__":
  args = get_args()

  params = set_params(args)

  main(params)