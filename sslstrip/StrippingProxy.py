# Copyright (c) 2004-2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

from twisted.web.http import HTTPChannel
from ClientRequest import ClientRequest

class StrippingProxy(HTTPChannel):
    '''sslstrip is, at heart, a transparent proxy server that does some unusual things.
    This is the basic proxy server class, where we get callbacks for GET and POST methods.
    We then proxy these out using HTTP or HTTPS depending on what information we have about
    the (connection, client_address) tuple in our cache.      
    '''

    requestFactory = ClientRequest
