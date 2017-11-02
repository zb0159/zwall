#!/bin/sh

sudo make
./mproxy -l 8081 -D -d
tail -f Log.log
