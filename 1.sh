#!/bin/sh


sudo kill -9 $(pidof mproxy)
sudo make clean
sudo vim mproxy.c

