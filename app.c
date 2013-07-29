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

#include "app.h"
#include "keys.h"
#include "keysdata.h"
#include "keysmngr.h"
#include "transforms.h"

/************************
 * Crypto Init/Shutdown *
 ************************/

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

/********************************************************
 * High level routines form xmlsec command line utility *
 ********************************************************/

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

/*************************
 * Crypto transforms ids *
 *************************/

PyObject *xmlsec_TransformAes128CbcId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformAes128CbcId));
}
PyObject *xmlsec_TransformAes192CbcId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformAes192CbcId));
}
PyObject *xmlsec_TransformAes256CbcId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformAes256CbcId));
}

/* only OPENSSL and NSS */
PyObject *xmlsec_TransformKWAes128Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformKWAes128Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL and NSS */
PyObject *xmlsec_TransformKWAes192Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformKWAes192Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL and NSS */
PyObject *xmlsec_TransformKWAes256Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformKWAes256Id));
#else
  return (NULL);
#endif
}

PyObject *xmlsec_TransformDes3CbcId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformDes3CbcId));
}

/* only OPENSSL and NSS */
PyObject *xmlsec_TransformKWDes3Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformKWDes3Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformDsaSha1Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, NSS and GNUTLS */
PyObject *xmlsec_TransformHmacMd5Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS || defined XMLSEC_CRYPTO_GNUTLS
  return (wrap_xmlSecTransformId(xmlSecTransformHmacMd5Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, NSS and GNUTLS */
PyObject *xmlsec_TransformHmacRipemd160Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS || defined XMLSEC_CRYPTO_GNUTLS
  return (wrap_xmlSecTransformId(xmlSecTransformHmacRipemd160Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, NSS and GNUTLS */
PyObject *xmlsec_TransformHmacSha1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS || defined XMLSEC_CRYPTO_GNUTLS
  return (wrap_xmlSecTransformId(xmlSecTransformHmacSha1Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformHmacSha224Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformHmacSha224Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformHmacSha256Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformHmacSha256Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformHmacSha384Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformHmacSha384Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformHmacSha512Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformHmacSha512Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformMd5Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformMd5Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL */
PyObject *xmlsec_TransformRipemd160Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL
  return (wrap_xmlSecTransformId(xmlSecTransformRipemd160Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaMd5Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaMd5Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaRipemd160Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaRipemd160Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformRsaSha1Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaSha224Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaSha224Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaSha256Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaSha256Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaSha384Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaSha384Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformRsaSha512Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformRsaSha512Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_TransformRsaPkcs1Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecTransformId(xmlSecTransformRsaPkcs1Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO */
PyObject *xmlsec_TransformRsaOaepId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO
  return (wrap_xmlSecTransformId(xmlSecTransformRsaOaepId));
#else
  return (NULL);
#endif
}

PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformSha1Id));
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformSha224Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformSha224Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformSha256Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformSha256Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformSha384Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformSha384Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL >= 0.9.8 */
PyObject *xmlsec_TransformSha512Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL && defined XMLSEC_OPENSSL_098
  return (wrap_xmlSecTransformId(xmlSecTransformSha512Id));
#else
  return (NULL);
#endif
}

/****************
 * Key data ids *
 ****************/

PyObject *xmlsec_KeyDataAesId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataAesId));
}
PyObject *xmlsec_KeyDataDesId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataDesId));
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataDsaId));
#else
  return (NULL);
#endif
}

/* only OPENSSL, NSS and GNUTLS */
PyObject *xmlsec_KeyDataHmacId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_NSS || defined XMLSEC_CRYPTO_GNUTLS
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataHmacId));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataRsaId));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataX509Id));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_KeyDataRawX509CertId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataRawX509CertId));
#else
  return (NULL);
#endif
}

/* only OPENSSL, MSCRYPTO and NSS */
PyObject *xmlsec_X509StoreId(PyObject *self, PyObject *args) {
#if defined XMLSEC_CRYPTO_OPENSSL || defined XMLSEC_CRYPTO_MSCRYPTO || defined XMLSEC_CRYPTO_NSS
  /* FIXME */
  return PyCObject_FromVoidPtr((void  *)xmlSecX509StoreId, NULL);
#else
  return (NULL);
#endif
}
