/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2013 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This is free software; see COPYING file in the source
 * distribution for preciese wording.
 */

#include "xmlsecmod.h"

#include "version.h"

PyObject *xmlsec_xmlsec_version(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION));
}

PyObject *xmlsec_xmlsec_version_major(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MAJOR));
}

PyObject *xmlsec_xmlsec_version_minor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MINOR));
}

PyObject *xmlsec_xmlsec_version_subminor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_SUBMINOR));
}

PyObject *xmlsec_xmlsec_version_info(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION_INFO));
}
