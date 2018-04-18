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

#include "keyinfo.h"
#include "keys.h"
#include "keysdata.h"
#include "keysmngr.h"
#include "list.h"
#include "transforms.h"
#include "xmlenc.h"

PyObject *wrap_xmlSecKeyInfoCtxPtr(xmlSecKeyInfoCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecKeyInfoCtxPtr", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *xmlSecKeyInfoCtx_getattr(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  const char *attr;

  if (CheckArgs(args, "OS:keyInfoCtxGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:keyInfoCtxGetAttr", &keyInfoCtx_obj,
			  &attr))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssssssssssss]", "flags",
			 "flags2", "keysMngr", "mode", "enabledKeyData",
			 "base64LineSize", "retrievalMethodCtx",
			 "maxRetrievalMethodLevel", "encCtx",
			 "maxEncryptedKeyLevel", "certsVerificationTime",
			 "certsVerificationDepth", "curRetrievalMethodLevel",
			 "keyReq");
  if (!strcmp(attr, "flags"))
    return (wrap_int(keyInfoCtx->flags));
  if (!strcmp(attr, "flags2"))
    return (wrap_int(keyInfoCtx->flags2));
  if (!strcmp(attr, "keysMngr"))
    return (wrap_xmlSecKeysMngrPtr(keyInfoCtx->keysMngr));
  if (!strcmp(attr, "mode"))
    return (wrap_int(keyInfoCtx->mode));
  if (!strcmp(attr, "enabledKeyData"))
    return (wrap_xmlSecPtrListPtr(&(keyInfoCtx->enabledKeyData)));
  if (!strcmp(attr, "base64LineSize"))
    return (wrap_int(keyInfoCtx->base64LineSize));
  if (!strcmp(attr, "retrievalMethodCtx"))
    return (wrap_xmlSecTransformCtxPtr(&(keyInfoCtx->retrievalMethodCtx)));
  if (!strcmp(attr, "maxRetrievalMethodLevel"))
    return (wrap_int(keyInfoCtx->maxRetrievalMethodLevel));
  if (!strcmp(attr, "encCtx"))
    return (wrap_xmlSecEncCtxPtr(keyInfoCtx->encCtx));
  if (!strcmp(attr, "maxEncryptedKeyLevel"))
    return (wrap_int(keyInfoCtx->maxEncryptedKeyLevel));
  if (!strcmp(attr, "certsVerificationTime"))
    return (wrap_int(keyInfoCtx->certsVerificationTime));
  if (!strcmp(attr, "certsVerificationDepth"))
    return (wrap_int(keyInfoCtx->certsVerificationDepth));
  if (!strcmp(attr, "curRetrievalMethodLevel"))
    return (wrap_int(keyInfoCtx->curRetrievalMethodLevel));
  if (!strcmp(attr, "curEncryptedKeyLevel"))
    return (wrap_int(keyInfoCtx->curEncryptedKeyLevel));
  if (!strcmp(attr, "keyReq"))
    return wrap_xmlSecKeyReqPtr(&(keyInfoCtx->keyReq));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecKeyInfoCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *value_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  const char *name;

  if (CheckArgs(args, "OS?:keyInfoCtxSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:keyInfoCtxSetAttr",
			  &keyInfoCtx_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
    
  if (!strcmp(name, "flags"))
    keyInfoCtx->flags = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "flags2"))
    keyInfoCtx->flags2 = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keysMngr"))
    keyInfoCtx->keysMngr = xmlSecKeysMngrPtr_get(value_obj);
  else if (!strcmp(name, "mode"))
    keyInfoCtx->mode = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "enabledKeyData"))
    keyInfoCtx->enabledKeyData = *(xmlSecPtrListPtr_get(value_obj));
  else if (!strcmp(name, "base64LineSize"))
    keyInfoCtx->base64LineSize = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "retrievalMethodCtx"))
    keyInfoCtx->retrievalMethodCtx = *(xmlSecTransformCtxPtr_get(value_obj));
  else if (!strcmp(name, "maxRetrievalMethodLevel"))
    keyInfoCtx->maxRetrievalMethodLevel = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "encCtx"))
    keyInfoCtx->encCtx = xmlSecEncCtxPtr_get(value_obj);
  else if (!strcmp(name, "maxEncryptedKeyLevel"))
    keyInfoCtx->maxEncryptedKeyLevel = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "certsVerificationTime"))
    keyInfoCtx->certsVerificationTime = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "certsVerificationDepth"))
    keyInfoCtx->certsVerificationDepth = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "curRetrievalMethodLevel"))
    keyInfoCtx->curRetrievalMethodLevel = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "curEncryptedKeyLevel"))
    keyInfoCtx->curEncryptedKeyLevel = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keyReq"))
    keyInfoCtx->keyReq = *(xmlSecKeyReqPtr_get(value_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_KeyInfoNodeRead(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *key_obj, *keyInfoCtx_obj;
  xmlNodePtr keyInfoNode;
  xmlSecKeyPtr key;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOO:keyInfoNodeRead")) {
    if (!PyArg_ParseTuple(args, "OOO:keyInfoNodeRead",
			  &keyInfoNode_obj, &key_obj, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  key = xmlSecKeyPtr_get(key_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyInfoNodeRead(keyInfoNode, key, keyInfoCtx)));
}

PyObject *xmlsec_KeyInfoNodeWrite(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *key_obj, *keyInfoCtx_obj;
  xmlNodePtr keyInfoNode;
  xmlSecKeyPtr key;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOO:keyInfoNodeWrite")) {
    if (!PyArg_ParseTuple(args, "OOO:keyInfoNodeWrite",
			  &keyInfoNode_obj, &key_obj, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  key = xmlSecKeyPtr_get(key_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyInfoNodeWrite(keyInfoNode, key, keyInfoCtx)));
}

PyObject *xmlsec_KeyInfoCtxCreate(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "o:keyInfoCtxCreate")) {
    if (!PyArg_ParseTuple(args, "O:keyInfoCtxCreate", &mngr_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  /* mngr may be NULL */
  keyInfoCtx = xmlSecKeyInfoCtxCreate(mngr);

  return (wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));
}

PyObject *xmlsec_KeyInfoCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "O:keyInfoCtxDestroy")) {
    if (!PyArg_ParseTuple(args, "O:keyInfoCtxDestroy", &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxDestroy(keyInfoCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *mngr_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeysMngrPtr mngr = NULL;

  if (CheckArgs(args, "Oo:keyInfoCtxInitialize")) {
    if (!PyArg_ParseTuple(args, "OO:keyInfoCtxInitialize", &keyInfoCtx_obj,
			  &mngr_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  /* mngr may be NULL */
  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  
  return (wrap_int(xmlSecKeyInfoCtxInitialize(keyInfoCtx, mngr)));
}

PyObject *xmlsec_KeyInfoCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "O:keyInfoCtxFinalize")) {
    if (!PyArg_ParseTuple(args, "O:keyInfoCtxFinalize", &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxFinalize(keyInfoCtx);
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxReset(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "O:keyInfoCtxReset")) {
    if (!PyArg_ParseTuple(args, "O:keyInfoCtxReset", &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxReset(keyInfoCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxCopyUserPref(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecKeyInfoCtxPtr dst;
  xmlSecKeyInfoCtxPtr src;

  if (CheckArgs(args, "OO:keyInfoCtxCopyUserPref")) {
    if (!PyArg_ParseTuple(args, "OO:keyInfoCtxCopyUserPref",
			  &dst_obj, &src_obj))
      return NULL;
  }
  else return NULL;

  dst = xmlSecKeyInfoCtxPtr_get(dst_obj);
  src = xmlSecKeyInfoCtxPtr_get(src_obj);

  return (wrap_int(xmlSecKeyInfoCtxCopyUserPref(dst, src)));
}

PyObject *xmlsec_KeyInfoCtxCreateEncCtx(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "O:keyInfoCtxCreateEncCtx")) {
    if (!PyArg_ParseTuple(args, "O:keyInfoCtxCreateEncCtx", &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyInfoCtxCreateEncCtx(keyInfoCtx)));
}

PyObject *xmlsec_KeyInfoCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *output_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  FILE *output;

  if (CheckArgs(args, "OF:keyInfoCtxDebugDump")) {
    if (!PyArg_ParseTuple(args, "OO:keyInfoCtxDebugDump",
			  &keyInfoCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecKeyInfoCtxDebugDump(keyInfoCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *output_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  FILE *output;

  if (CheckArgs(args, "OF:keyInfoCtxDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "OO:keyInfoCtxDebugXmlDump",
			  &keyInfoCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecKeyInfoCtxDebugXmlDump(keyInfoCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataNameId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataNameId));
}
PyObject *xmlsec_KeyDataValueId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataValueId));
}
PyObject *xmlsec_KeyDataRetrievalMethodId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataRetrievalMethodId));
}
PyObject *xmlsec_KeyDataEncryptedKeyId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyDataId(xmlSecKeyDataEncryptedKeyId));
}
