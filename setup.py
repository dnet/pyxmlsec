#!/usr/bin/env python

# $Id$
#
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
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

classifiers = """\
Development Status :: 1 - Pre-Alpha
Intended Audience :: Developers
License :: OSI Approved :: GNU General Public License (GPL)
Operating System :: MacOS :: MacOS X
Operating System :: POSIX :: Linux
Programming Language :: C
Programming Language :: Python
Topic :: Software Development :: Libraries :: Python Modules
"""

from distutils.core import setup, Extension
import commands

#print commands.getoutput('pkg-config libxml-2.0 --cflags')
#print commands.getoutput('pkg-config libxml-2.0 --libs')
#print commands.getoutput('pkg-config xmlsec1 --cflags')
#print commands.getoutput('pkg-config xmlsec1 --libs')

em = Extension("xmlsecmod",
               sources = ["wrap_objs.c",
                          "xmlsecmod.c", "app.c", "base64.c", "buffer.c",
                          "keyinfo.c", "keys.c", "keysdata.c", "keysmngr.c",
                          "list.c", "membuf.c", "nodeset.c", "parser.c",
                          "templates.c", "transforms.c", "version.c",
                          "xmldsig.c", "xmlenc.c", "xmlsec.c", "xmltree.c",
                          "x509.c",
                          "openssl.c"],
               define_macros = [('XMLSEC_NO_XKMS', '1'),
                                ('XMLSEC_CRYPTO', 'openssl'),
                                ('XMLSEC_CRYPTO_OPENSSL', '1')],
               include_dirs  = ["/usr/local/include/xmlsec1/",
                                "/usr/include/libxml2/"],
               library_dirs  = ["/usr/lib", "/usr/local/lib"],
               libraries     = ["xmlsec1-openssl", "xmlsec1", "crypto",
                                "xslt", "xml2", "pthread", "z" ,"m"]
               )

setup(name = "pyxmlsec",
      version = "0.20040113",
      description = "A set of Python bindings for XML Security Library (XMLSec)",
      long_description = "",
      author = "Valery Febvre",
      author_email = "vfebvre@easter-eggs.com",
      license = "GNU GPL",
      platforms = ["any"],
      url = "http://pyxmlsec.labs.libre-entreprise.org",
      ext_modules = [em],
      py_modules = ["xmlsec", "xmlsec_strings"]
)
