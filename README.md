# Intro
Simple and trivial port forwarder written in python

usage example:

Simple port forwarding

    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443

Port forwarding with packets dump

    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443 -d dumpfile.dmp -df RAW
    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443 -d dumpfile.dmp -df HEX

File output

    [IN PACKET]
    0000   48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D    HTTP/1.1 200 OK.
    0010   0A 44 61 74 65 3A 20 4D 6F 6E 2C 20 32 35 20 4A    .Date: Mon, 25 J
    0020   61 6E 20 32 30 31 36 20 31 34 3A 35 34 3A 34 36    an 2016 14:54:46
    0030   20 47 4D 54 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79     GMT..Content-Ty
    0040   70 65 3A 20 74 65 78 74 2F 68 74 6D 6C 0D 0A 45    pe: text/html..E
    0050   78 70 69 72 65 73 3A 20 54 68 75 2C 20 31 39 20    xpires: Thu, 19
    0060   4E 6F 76 20 31 39 38 31 20 30 38 3A 35 32 3A 30    Nov 1981 08:52:0
    0070   30 20 47 4D 54 0D 0A 43 61 63 68 65 2D 43 6F 6E    0 GMT..Cache-Con
    0080   74 72 6F 6C 3A 20 6E 6F 2D 73 74 6F 72 65 2C 20    trol: no-store,
    0090   6E 6F 2D 63 61 63 68 65 2C 20 6D 75 73 74 2D 72    no-cache, must-r
    00A0   65 76 61 6C 69 64 61 74 65 2C 20 70 6F 73 74 2D    evalidate, post-
    00B0   63 68 65 63 6B 3D 30 2C 20 70 72 65 2D 63 68 65    check=0, pre-che
    00C0   63 6B 3D 30 0D 0A 50 72 61 67 6D 61 3A 20 6E 6F    ck=0..Pragma: no
    00D0   2D 63 61 63 68 65 0D 0A 56 61 72 79 3A 20 41 63    -cache..Vary: Ac
    00E0   63 65 70 74 2D 45 6E 63 6F 64 69 6E 67 0D 0A 53    cept-Encoding..S
    00F0   65 72 76 65 72 3A 20 63 6C 6F 75 64 66 6C 61 72    erver: cloudflar
    0100   65 2D 6E 67 69 6E 78 0D 0A 43 46 2D 52 41 59 3A    e-nginx..CF-RAY:
    0110   20 32 36 61 34 64 30 62 33 62 39 34 61 32 62 63     26a4d0b3b94a2bc
    0120   34 2D 41 4D 53 0D 0A 43 6F 6E 74 65 6E 74 2D 45    4-AMS..Content-E
    0130   6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 0D 0A 43    ncoding: gzip..C
    0140   6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 31    ontent-Length: 1
    0150   36 33 32 38 0D 0A 41 67 65 3A 20 32 0D 0A 56 69    6328..Age: 2..Vi
    0160   61 3A 20 31 2E 31 20 77 63 67 2D 69 6E 70 73 2D    a: 1.1 wcg-inps-
    0170   63 6C 75 73 74 65 72 0D 0A 43 6F 6E 6E 65 63 74    cluster..Connect
    0180   69 6F 6E 3A 20 63 6C 6F 73 65 0D 0A 0D 0A          ion: close....

HTTP Packet inspect

    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443 --dump-http-req

Output

    dzonerzy$ python py-forwarder.py -f 0.0.0.0:8888 -t 127.0.0.1:3128 --dump-http-req
    [!] Starting port forwarding (0.0.0.0:8888 => 127.0.0.1:3128)
    [*] Received connection from 127.0.0.1
    [HTTP] GET => www.repubblica.it
    [HTTP] GET => pit.lp4.io
    [HTTP] GET => oasjs.kataweb.it
    [HTTP] GET => scripts.kataweb.it
    [HTTP] GET => www.repubblica.it
    [HTTP] GET => www.repubblica.it
    [HTTP] GET => www.repstatic.it
    [HTTP] GET => p.lp4.io
    ^C
    [!] Byeeee
    [INFO] Total byte sent 26118
    [INFO] Total byte received 174743


Help

    py-forwarder.py -h
    py-forwarder.py --help
