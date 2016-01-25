# Intro
Simple and trivial port forwarder written in python

usage example:

Simple port forwarding

    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443

Port forwarding with packets dump

    py-forwarder.py -f 127.0.0.1:8080 -t 127.0.0.1:443 -d dumpfile.dmp
