/* $Id$ 
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
#include "keysmngr.h"

/* Crypto Init/Shutdown */

PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args) {
  int ret;
  ret = xmlSecCryptoInit();
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args) {
  int ret;
  ret = xmlSecCryptoShutdown();
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoKeysMngrInit(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  int ret;

  if (!PyArg_ParseTuple(args, "O:cryptoKeysMngrInit", &mngr_obj))
    return NULL;
  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  ret = xmlSecCryptoKeysMngrInit(mngr);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

/* High level routines form xmlsec command line utility */

PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args) {
  char *config;
  int ret;
  if (!PyArg_ParseTuple(args, "z:cryptoAppInit", &config))
    return NULL;
  ret = xmlSecCryptoAppInit(config);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args) {
  int ret;
  ret = xmlSecCryptoAppShutdown();
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrInit(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  int ret;

  if (!PyArg_ParseTuple(args, "O:cryptoAppDefaultKeysMngrInit", &mngr_obj))
    return NULL;
  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  ret = xmlSecCryptoAppDefaultKeysMngrInit(mngr);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrAdoptKey(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *key_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyPtr key;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:cryptoAppDefaultKeysMngrAdoptKey", &mngr_obj, &key_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  key = xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  ret = xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(mngr, key);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrLoad(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *uri;
  int ret;

  if (!PyArg_ParseTuple(args, "Os:cryptoAppDefaultKeysMngrLoad", &mngr_obj, &uri))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  ret = xmlSecCryptoAppDefaultKeysMngrLoad(mngr, uri);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrSave(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *filename;
  xmlSecKeyDataType type;
  int ret;

  if (!PyArg_ParseTuple(args, "Osi:cryptoAppDefaultKeysMngrSave", &mngr_obj,
			&filename, &type))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  ret = xmlSecCryptoAppDefaultKeysMngrSave(mngr, filename, type);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppKeysMngrCertLoad(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *filename;
  xmlSecKeyDataFormat format;
  xmlSecKeyDataType type;
  int ret;

  if (!PyArg_ParseTuple(args, "Osii:cryptoAppKeysMngrCertLoad", &mngr_obj,
			&filename, &format, &type))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  ret = xmlSecCryptoAppKeysMngrCertLoad(mngr, filename, format, type);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args) {
  const char *filename;
  int format;
  const char *pwd;
  PyObject *pwd_callback_obj;
  PyObject *pwd_callback_ctx_obj;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "sizOO:cryptoAppKeyLoad", &filename, &format,
			&pwd, &pwd_callback_obj, &pwd_callback_ctx_obj))
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
/* Key data ids */
PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataDsaId, NULL);
}
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRsaId, NULL);
}
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataX509Id, NULL);
}
