/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
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

#include "xmlsecmod.h"

#include "app.h"
#include "keys.h"
#include "keysmngr.h"

/* Crypto Init/Shutdown */

PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCryptoInit()));
}

PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCryptoShutdown()));
}

PyObject *xmlsec_CryptoKeysMngrInit(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (CheckArgs(args, "O:cryptoKeysMngrInit")) {
    if (!PyArg_ParseTuple(args, "O:cryptoKeysMngrInit", &mngr_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_int(xmlSecCryptoKeysMngrInit(mngr)));
}

/* High level routines form xmlsec command line utility */

PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args) {
  const char *config = NULL;

  if (CheckArgs(args, "s:cryptoAppInit")) {
    if (!PyArg_ParseTuple(args, "z:cryptoAppInit", &config))
      return NULL;
  }
  else return NULL;

  return (wrap_int(xmlSecCryptoAppInit(config)));
}

PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCryptoAppShutdown()));
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrInit(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (CheckArgs(args, "O:cryptoAppDefaultKeysMngrInit")) {
    if (!PyArg_ParseTuple(args, "O:cryptoAppDefaultKeysMngrInit", &mngr_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_int(xmlSecCryptoAppDefaultKeysMngrInit(mngr)));
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrAdoptKey(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *key_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:cryptoAppDefaultKeysMngrAdoptKey")) {
    if (!PyArg_ParseTuple(args, "OO:cryptoAppDefaultKeysMngrAdoptKey",
			  &mngr_obj, &key_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_int(xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key)));
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrLoad(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *uri;

  if (CheckArgs(args, "OS:cryptoAppDefaultKeysMngrLoad")) {
    if (!PyArg_ParseTuple(args, "Os:cryptoAppDefaultKeysMngrLoad", &mngr_obj,
			  &uri))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_int(xmlSecCryptoAppDefaultKeysMngrLoad(mngr, uri)));
}

PyObject *xmlsec_CryptoAppDefaultKeysMngrSave(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *filename;
  xmlSecKeyDataType type;

  if (CheckArgs(args, "OSI:cryptoAppDefaultKeysMngrSave")) {
    if (!PyArg_ParseTuple(args, "Osi:cryptoAppDefaultKeysMngrSave", &mngr_obj,
			  &filename, &type))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_int(xmlSecCryptoAppDefaultKeysMngrSave(mngr, filename, type)));
}

PyObject *xmlsec_CryptoAppKeysMngrCertLoad(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *filename;
  xmlSecKeyDataFormat format;
  xmlSecKeyDataType type;
  int ret;

  if (CheckArgs(args, "OSII:cryptoAppKeysMngrCertLoad")) {
    if (!PyArg_ParseTuple(args, "Osii:cryptoAppKeysMngrCertLoad", &mngr_obj,
			  &filename, &format, &type))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  ret = xmlSecCryptoAppKeysMngrCertLoad(mngr, filename, format, type);

  return (wrap_int(ret));
}

PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args) {
  PyObject *pwdCallback_obj, *pwdCallbackCtx_obj;
  const char *filename;
  xmlSecKeyDataFormat format;
  const char *pwd = NULL;
  void *pwdCallback = NULL;
  void *pwdCallbackCtx = NULL;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "SIscc:cryptoAppKeyLoad")) {
    if (!PyArg_ParseTuple(args, "sizOO:cryptoAppKeyLoad", &filename, &format,
			  &pwd, &pwdCallback_obj, &pwdCallbackCtx_obj))
    return NULL;
  }
  else return NULL;

  /* FIXME */
  if (pwdCallback_obj != Py_None) {
    pwdCallback = PyCObject_AsVoidPtr(pwdCallback_obj);
  }
  if (pwdCallbackCtx_obj != Py_None) {
    pwdCallbackCtx = PyCObject_AsVoidPtr(pwdCallbackCtx_obj);
  }
  key = xmlSecCryptoAppKeyLoad(filename, format, pwd,
			       pwdCallback, pwdCallbackCtx);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_CryptoAppPkcs12Load(PyObject *self, PyObject *args) {
  PyObject *pwdCallback_obj, *pwdCallbackCtx_obj;
  const char *filename;
  const char *pwd = NULL;
  void *pwdCallback = NULL;
  void *pwdCallbackCtx = NULL;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "Sscc:cryptoAppPkcs12Load")) {
    if (!PyArg_ParseTuple(args, "szOO:cryptoAppPkcs12Load", &filename, &pwd,
			  &pwdCallback_obj, &pwdCallbackCtx_obj))
      return NULL;
  }
  else return NULL;

  /* FIXME */
  if (pwdCallback_obj != Py_None) {
    pwdCallback = PyCObject_AsVoidPtr(pwdCallback_obj);
  }
  if (pwdCallbackCtx_obj != Py_None) {
    pwdCallbackCtx = PyCObject_AsVoidPtr(pwdCallbackCtx_obj);
  }
  key = xmlSecCryptoAppPkcs12Load(filename, pwd, pwdCallback, pwdCallbackCtx);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_CryptoAppKeyCertLoad(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  const char *filename;
  xmlSecKeyDataFormat format;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OSI:cryptoAppKeyCertLoad")) {
    if (!PyArg_ParseTuple(args, "Osi:cryptoAppKeyCertLoad", &key_obj,
			  &filename, &format))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_int(xmlSecCryptoAppKeyCertLoad(key, filename, format)));
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

/* only OPENSSL */
PyObject *xmlsec_TransformKWAes128Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes128Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformKWAes192Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes192Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformKWAes256Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWAes256Id, NULL);
#else
  return (NULL);
#endif
}

PyObject *xmlsec_TransformDes3CbcId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformDes3CbcId, NULL);
}

/* only OPENSSL */
PyObject *xmlsec_TransformKWDes3Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformKWDes3Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformDsaSha1Id, NULL);
#else
  return (NULL);
#endif
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

/* only OPENSSL */
PyObject *xmlsec_TransformRipemd160Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRipemd160Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaSha1Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformRsaPkcs1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaPkcs1Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformRsaOaepId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecTransformRsaOaepId, NULL);
#else
  return (NULL);
#endif
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

/* only OPENSSL */
PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataDsaId, NULL);
#else
  return (NULL);
#endif
}

PyObject *xmlsec_KeyDataHmacId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataHmacId, NULL);
}

/* only OPENSSL */
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRsaId, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataX509Id, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_KeyDataRawX509CertId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRawX509CertId, NULL);
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_X509StoreId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return PyCObject_FromVoidPtr((void  *)xmlSecX509StoreId, NULL);
#else
  return (NULL);
#endif
}
