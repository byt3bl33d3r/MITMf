Originally, sergio-proxy was a standalone implementation of a
transparent proxy using the Twisted networking framework
for Python. However, sslstrip uses almost *exactly* the
same interception method, so I decided to use sslstrip's
more mature libraries and try to provide a simple plugin
interface to grab the data.

The only file that has been modified from sslstrip is the
ServerConnection.py file, from which we can hook at certain
important points during the intercept.

Copyright 2011, Ben Schmidt
Released under the GPLv3
