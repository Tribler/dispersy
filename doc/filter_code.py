#!/usr/bin/env python

import sys

def extract(begin, end):
    filter_ = True
    for line in sys.stdin:
        if line.startswith(begin):
            filter_ = False

        elif line.startswith(end):
            if not filter_:
                print
            filter_ = True

        elif not filter_:
            print line.rstrip()

def main():
    mapping = {"python":("#+BEGIN_SRC python", "#+END_SRC"),
               "bash":("#+BEGIN_SRC bash", "#+END_SRC"),
               "sh":("#+BEGIN_SRC sh", "#+END_SRC")}

    if len(sys.argv) >= 2 and sys.argv[1] in mapping:
        begin, end = mapping[sys.argv[1]]
        extract(begin, end)

    else:
        print "Usage:", sys.argv[0], "[python|bash|sh]"

if __name__ == "__main__":
    main()
