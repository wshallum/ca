#!/bin/sh
aclocal -W all 
automake -W all --add-missing
autoconf -W all
