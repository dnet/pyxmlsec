/* $id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003
 * http://
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <Python.h>
#include <xmlsec/crypto.h>

#include "xmlsecmod.h"
#include "keys.h"

PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args) {
  char *config;
  int result;
  if (!PyArg_ParseTuple(args, "z", &config))
    return NULL;
  result = xmlSecCryptoAppInit(config);
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecCryptoAppShutdown();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecCryptoInit();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecCryptoShutdown();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args) {
  const char *filename;
  int format;
  const char *pwd;
  PyObject *obj_pwd_callback;
  PyObject *obj_pwd_callback_ctx;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "sizOO", &filename, &format, &pwd,
			&obj_pwd_callback, &obj_pwd_callback_ctx))
    return NULL;

  key = xmlSecCryptoAppKeyLoad(filename, format, NULL, NULL, NULL);
  ret = PyCObject_FromVoidPtrAndDesc((void *) key, (char *) "xmlSecKeyPtr", NULL);
  return (PyObject *)ret;
}

/* Crypto transforms ids */
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformDsaSha1Id, NULL);
}
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaSha1Id, NULL);
}
PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformSha1Id, NULL);
}
