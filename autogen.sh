#!/bin/sh
aclocal -I m4
libtoolize --force -c
automake --add-missing -c
autoconf
