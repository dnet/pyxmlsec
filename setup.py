#!/usr/bin/env python

# $Id$
#
# pyxmlsec -- A Python binding for XML Security library (XMLSec)
#
# Copyright (C) 2003
# http://
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from distutils.core import setup, Extension

setup(name = "pyxmlsec",
      version = "0.1",
      description = "Python binding for XML Security Library (XMLSec)",
      long_description = ''' ''',
      author = "Valery Febvre",
      author_email="vfebvre@easter-eggs.com",
      url = "http://",
      ext_modules = [Extension("xmlsecmod",
                               sources = ["xmlsecmod.c", "xmlsec.c", "xmltree.c",
                                          "xmldsig.c", "crypto.c", "openssl.c",
                                          "templates.c", "transforms.c", "keys.c"],
                               define_macros = [('XMLSEC_NO_XKMS', '1'),
                                                ('XMLSEC_CRYPTO', 'openssl'),
                                                ('XMLSEC_CRYPTO_OPENSSL', '1')],
                               include_dirs = ["/usr/include/xmlsec1/",
                                               "/usr/include/libxml2/"],
                               library_dirs = ["/usr/lib"],
                               libraries = ["xmlsec1-openssl", "xmlsec1", "crypto",
                                            "xslt", "xml2", "pthread", "z" ,"m"],
                               )],
      py_modules = ["xmlsec", "xmlsec_strings"]
)

