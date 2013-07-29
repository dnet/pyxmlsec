/* $Id$ 
 *
 * PyXMLSec -- Python bindings for XML Security library (XMLSec)
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

#include "xmlsec.h"

PyObject *xmlsec_Init(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecInit()));
}

PyObject *xmlsec_Shutdown(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecShutdown()));
}

PyObject *xmlsec_CheckVersionExact(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCheckVersionExact()));
}

PyObject *xmlsec_CheckVersion(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCheckVersion()));
}

PyObject *xmlsec_CheckVersionExt(PyObject *self, PyObject *args) {
  int major;
  int minor;
  int subminor;
  xmlSecCheckVersionMode mode;
  
  if (CheckArgs(args, "IIII:checkVersionExt")) {
    if(!PyArg_ParseTuple(args, (char *) "iiii:checkVersionExt",
			 &major, &minor, &subminor, &mode))
      return NULL;
  }
  else return NULL;

  return (wrap_int(xmlSecCheckVersionExt(major, minor, subminor, mode)));
}
