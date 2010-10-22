#!/bin/sh
libtoolize --force -c
aclocal -I m4
automake --add-missing -c
autoconf
