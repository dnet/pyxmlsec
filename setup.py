#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# $Id$
#
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
#
# Author: Valéry Febvre <vfebvre@easter-eggs.com>
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

__doc__ = """Python bindings for XMLSec Library

PyXMLSec is a set of Python bindings for XML Security Library (XMLSec).
"""

from distutils.core import setup, Extension
import sys, commands

# check python version
if not hasattr(sys, 'version_info') or sys.version_info < (2,2):
    raise SystemExit, "PyXMLSec requires Python version 2.2 or above."

# sanity check for any arguments
if len(sys.argv) == 1:
    msg = 'Choose an action :\n' \
          '   1. Build\n' \
          '   2. Install\n' \
          '   3. Clean\n' \
          '   4. Exit\n' \
          'Your choice : '
    reply = raw_input(msg)
    choice = None
    if reply:
        choice = reply[0]
    if choice == '1':
        sys.argv.append('build')
    elif choice == '2':
        sys.argv.append('install')
    elif choice == '3':
        sys.argv.append('clean')
        sys.argv.append('-a')
    elif choice == '4':
        sys.exit(0)

# the crypto engine name : openssl, gnutls or nss
xmlsec1_crypto = "openssl"
if 'build' in sys.argv:
    msg = '\nChoose a crypto engine :\n' \
          '   1. OpenSSL\n' \
          '   2. GnuTLS\n' \
          '   3. NSS\n' \
          'Your choice : '
    reply = raw_input(msg)
    choice = None
    if reply:
        choice = reply[0]
    if choice == '1':
        xmlsec1_crypto = "openssl"
    elif choice == '2':
        xmlsec1_crypto = "gnutls"
    elif choice == '3':
        xmlsec1_crypto = "nss"

define_macros = []
include_dirs  = []
library_dirs  = []
libraries     = []

def extract_cflags(cflags):
    global define_macros, include_dirs
    xmlsec_openssl_prefix = 'XMLSEC_OPENSSL_'

    list = cflags.split(' ')
    for flag in list:
        if flag == '':
            continue
        flag = flag.replace("\\\"", "")
        if flag[:2] == "-I":
            if flag[2:] not in include_dirs:
                include_dirs.append(flag[2:])
        elif flag[:2] == "-D":
            t = tuple(flag[2:].split('='))
            if len(t) == 1:
                t = (t[0], None) 

            # Problem: app.c only checks XMLSEC_OPENSSL_098,
            # but newer OpenSSL libs emit other flags such as
            # XMLSEC_OPENSSL_100
            #
            # Assumption: Methods provided by OpenSSL 098 will still
            # be provided by newer versions of OpenSSL.
            #
            # Solution: Add the old flag for newer OpenSSL libs.
            #
            # See https://github.com/dnet/pyxmlsec/issues/4
            if t[0].startswith(xmlsec_openssl_prefix) and t[1] == '1':
                version_as_string = t[0][len(xmlsec_openssl_prefix):]
                try:
                    version = int(version_as_string)
                    if version > 98:
                        hacked_t = (xmlsec_openssl_prefix + '098', t[1])
                        if hacked_t not in define_macros:
                            define_macros.append(hacked_t)
                except Exception as ex:
                    print "Warning: I thought %s was a version flag but I don't understand %s as a number." % (repr(t), repr(version_as_string))

            if t not in define_macros:
                define_macros.append(t)
        else:
            print "Warning : cflag %s skipped" % flag

def extract_libs(libs):
    global library_dirs, libraries
    list = libs.split(' ')
    for flag in list:
        if flag == '':
            continue
        if flag[:2] == "-l":
            if flag[2:] not in libraries:
                libraries.append(flag[2:])
        elif flag[:2] == "-L":
            if flag[2:] not in library_dirs:
                library_dirs.append(flag[2:])
        else:
            print "Warning : linker flag %s skipped" % flag


libxml2_cflags = commands.getoutput('pkg-config libxml-2.0 --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    libxml2_cflags = commands.getoutput('xml2-config --cflags')
if libxml2_cflags[:2] not in ["-I", "-D"]:
    print "Error : cannot get LibXML2 pre-processor and compiler flags"

libxml2_libs = commands.getoutput('pkg-config libxml-2.0 --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    libxml2_libs = commands.getoutput('xml2-config --libs')
if libxml2_libs[:2] not in ["-l", "-L"]:
    print "Error : cannot get LibXML2 linker flags"

cmd = 'pkg-config xmlsec1-%s --cflags' % xmlsec1_crypto
xmlsec1_cflags = commands.getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    cmd = 'xmlsec1-config --cflags --crypto=%s' % xmlsec1_crypto
    xmlsec1_cflags = commands.getoutput(cmd)
if xmlsec1_cflags[:2] not in ["-I", "-D"]:
    print "Error : cannot get XMLSec1 pre-processor and compiler flags"

cmd = 'pkg-config xmlsec1-%s --libs' % xmlsec1_crypto
xmlsec1_libs = commands.getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    cmd = 'xmlsec1-config --libs --crypto=%s' % xmlsec1_crypto
    xmlsec1_libs = commands.getoutput(cmd)
if xmlsec1_libs[:2] not in ["-l", "-L"]:
    print "Error : cannot get XMLSec1 linker flags"

#print libxml2_cflags
#print libxml2_libs
#print xmlsec1_cflags
#print xmlsec1_libs

extract_cflags(libxml2_cflags)
extract_libs(libxml2_libs)

extract_cflags(xmlsec1_cflags)
extract_libs(xmlsec1_libs)

#print define_macros
#print include_dirs
#print library_dirs
#print libraries

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Natural Language :: English',
    'Operating System :: POSIX',
    'Programming Language :: C',
    'Programming Language :: Python',
    'Topic :: Security',
    'Topic :: Software Development :: Libraries :: Python Modules',
    ]

em = Extension("xmlsecmod",
               sources = ["utils.c", "wrap_objs.c",
                          "app.c", "base64.c", "buffer.c", "errors.c",
                          "keyinfo.c", "keys.c", "keysdata.c", "keysmngr.c",
                          "list.c", "membuf.c", "nodeset.c", "parser.c",
                          "templates.c", "transforms.c", "version.c",
                          "xmldsig.c", "xmlenc.c", "xmlsec.c", "xmltree.c",
                          "x509.c",
                          "xmlsecmod.c"],
               define_macros = define_macros,
               include_dirs  = include_dirs,
               library_dirs  = library_dirs,
               libraries     = libraries
               )

doclines = __doc__.split("\n")

setup(name = "pyxmlsec",
      version = "0.4.0",
      description = doclines[0],
      long_description = "\n" . join(doclines[2:]),
      author = "Valery Febvre",
      author_email = "vfebvre@easter-eggs.com",
      license = "GNU GPL",
      platforms = ["any"],
      url = "http://pyxmlsec.labs.libre-entreprise.org",
      classifiers = classifiers,
      download_url = 'https://labs.libre-entreprise.org/frs/?group_id=17',
      ext_modules = [em],
      py_modules = ["xmlsec", "xmlsec_strings"]
)
