#!/usr/bin/env python
# $Id$

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

