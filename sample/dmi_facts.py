
import argparse
import os
import re
import socket
import sys
import warnings
warnings.filterwarnings('ignore')
import subprocess

class DMIIncoder(object):

    def __init__(self):
        self.result = ""

    def get_dmi(self):
        stream = os.popen("ls")
        if stream:
            self.result = hash(stream.read())


    def get_results(self):
        print self.result


if __name__ == "__main__":
    incoder = DMIIncoder()
    incoder.get_dmi()
    incoder.get_results()

