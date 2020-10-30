# -*- coding: utf-8 -*-
#!/usr/bin/python
import re

C1 = 'users:(("java",pid=22768,fd=52))'
C2 = 'users:(("nginx",pid=7306,fd=8),("nginx",pid=7305,fd=8),("nginx",pid=7304,fd=8),("nginx",pid=7303,fd=8),("nginx",pid=7302,fd=8))'

regex = re.compile(r"users:\(\(|\)\)", re.IGNORECASE)
r1 = regex.sub("", C1)
r2 = regex.sub("", C2)
r3 = r2.split('),(')

r4 = re.split(r"\),\(",r1)
for line in r2.split('),('):
  print line


print r1
print r2
