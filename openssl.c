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

#include "wrap_objs.h"

#include "openssl.h"

PyObject *xmlsec_OpenSSLAppInit(PyObject *self, PyObject *args) {
  char *config;
  int result;
  if (!PyArg_ParseTuple(args, "z:openSSLAppInit", &config))
    return NULL;
  result = xmlSecOpenSSLAppInit(config);
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_OpenSSLInit(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecOpenSSLInit();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}
