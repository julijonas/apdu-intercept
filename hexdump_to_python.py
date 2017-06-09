from __future__ import print_function

import re
import sys

pattern = re.compile(r' {2}(([0-9A-F][0-9A-F] )*[0-9A-F][0-9A-F]) {2}')

separated = True
for line in sys.stdin:
    result = pattern.search(line)
    if result:
        if separated:
            separated = False
            print("'''")
        print(result.group(1))
    elif not separated:
        separated = True
        print("''',")

if not separated:
    print("''',")
