/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org/
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
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args) {
  int ret;

  ret = xmlSecCryptoShutdown();
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

  return Py_BuildValue("i", ret);
}

/* High level routines form xmlsec command line utility */

PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args) {
  char *config;
  int ret;
  if (!PyArg_ParseTuple(args, "z:cryptoAppInit", &config))
    return NULL;
  ret = xmlSecCryptoAppInit(config);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args) {
  int ret;

  ret = xmlSecCryptoAppShutdown();
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

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args) {
  const char *filename;
  xmlSecKeyDataFormat format;
  const char *pwd = NULL;
  PyObject *pwdCallback_obj;
  PyObject *pwdCallbackCtx_obj;
  void *pwdCallback = NULL;
  void *pwdCallbackCtx = NULL;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "sizOO:cryptoAppKeyLoad", &filename, &format,
			&pwd, &pwdCallback_obj, &pwdCallbackCtx_obj))
    return NULL;

  if (pwdCallback_obj != Py_None) {
    pwdCallback = PyCObject_AsVoidPtr(pwdCallback_obj);
  }
  if (pwdCallbackCtx_obj != Py_None) {
    pwdCallbackCtx = PyCObject_AsVoidPtr(pwdCallbackCtx_obj);
  }
  key = xmlSecCryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx);
  ret = PyCObject_FromVoidPtrAndDesc((void *) key, (char *) "xmlSecKeyPtr", NULL);
  return (PyObject *)ret;
}

PyObject *xmlsec_CryptoAppPkcs12Load(PyObject *self, PyObject *args) {
  const char *filename;
  const char *pwd = NULL;
  PyObject *pwd_callback_obj = NULL;
  PyObject *pwd_callback_ctx_obj = NULL;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "szOO:cryptoAppPkcs12Load", &filename, &pwd,
			&pwd_callback_obj, &pwd_callback_ctx_obj))
    return NULL;

  key = xmlSecCryptoAppPkcs12Load(filename, pwd,
				  PyCObject_AsVoidPtr(pwd_callback_obj),
				  PyCObject_AsVoidPtr(pwd_callback_ctx_obj));

  ret = PyCObject_FromVoidPtrAndDesc((void *) key, (char *) "xmlSecKeyPtr", NULL);
  return (PyObject *)ret;
}

PyObject *xmlsec_CryptoAppKeyCertLoad(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  const char *filename;
  xmlSecKeyDataFormat format;
  xmlSecKeyPtr key;
  int ret;

  if (!PyArg_ParseTuple(args, "Osi:cryptoAppKeyCertLoad", &key_obj, &filename,
			&format))
    return NULL;

  key = xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  ret  = xmlSecCryptoAppKeyCertLoad(key, filename, format);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_CryptoAppGetDefaultPwdCallback(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecCryptoAppGetDefaultPwdCallback, NULL);
}

/* Crypto transforms ids */
PyObject *xmlsec_TransformAes128CbcId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformAes128CbcId, NULL);
}
PyObject *xmlsec_TransformAes192CbcId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformAes192CbcId, NULL);
}
PyObject *xmlsec_TransformAes256CbcId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformAes256CbcId, NULL);
}
PyObject *xmlsec_TransformKWAes128Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes128Id, NULL);
}
PyObject *xmlsec_TransformKWAes192Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes192Id, NULL);
}
PyObject *xmlsec_TransformKWAes256Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes256Id, NULL);
}
PyObject *xmlsec_TransformDes3CbcId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformDes3CbcId, NULL);
}
PyObject *xmlsec_TransformKWDes3Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWDes3Id, NULL);
}
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformDsaSha1Id, NULL);
}
PyObject *xmlsec_TransformHmacSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformHmacSha1Id, NULL);
}
PyObject *xmlsec_TransformHmacRipemd160Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformHmacRipemd160Id, NULL);
}
PyObject *xmlsec_TransformHmacMd5Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformHmacMd5Id, NULL);
}
PyObject *xmlsec_TransformRipemd160Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRipemd160Id, NULL);
}
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaSha1Id, NULL);
}
PyObject *xmlsec_TransformRsaPkcs1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaPkcs1Id, NULL);
}
PyObject *xmlsec_TransformRsaOaepId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaOaepId, NULL);
}
PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformSha1Id, NULL);
}
/* Key data ids */
PyObject *xmlsec_KeyDataAesId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataAesId, NULL);
}
PyObject *xmlsec_KeyDataDesId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataDesId, NULL);
}
PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataDsaId, NULL);
}
PyObject *xmlsec_KeyDataHmacId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataHmacId, NULL);
}
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRsaId, NULL);
}
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataX509Id, NULL);
}
PyObject *xmlsec_KeyDataRawX509CertId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRawX509CertId, NULL);
}
PyObject *xmlsec_X509StoreId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecX509StoreId, NULL);
}
