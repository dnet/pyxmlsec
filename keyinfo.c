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

#include "wrap_objs.h"

#include "keyinfo.h"
#include "keys.h"
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

  if (!PyArg_ParseTuple(args, "Os:keyInfoCtxGetAttr", &keyInfoCtx_obj, &attr))
    return NULL;

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
  if (!strcmp(attr, "keyReq"))
    return wrap_xmlSecKeyReqPtr(&(keyInfoCtx->keyReq));
  /* TODO */

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecKeyInfoCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *value_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  const char *name;

  if (!PyArg_ParseTuple(args, "OsO:keyInfoCtxSetAttr",
			&keyInfoCtx_obj, &name, &value_obj))
    return NULL;

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
  else if (!strcmp(name, "keyReq"))
    keyInfoCtx->keyReq = *(xmlSecKeyReqPtr_get(value_obj));
  /* TODO */

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_KeyInfoNodeRead(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *key_obj, *keyInfoCtx_obj;
  xmlNodePtr keyInfoNode;
  xmlSecKeyPtr key;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "OOO:keyInfoNodeRead",
			&keyInfoNode_obj, &key_obj, &keyInfoCtx_obj))
    return NULL;

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

  if (!PyArg_ParseTuple(args, "OOO:keyInfoNodeWrite",
			&keyInfoNode_obj, &key_obj, &keyInfoCtx_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  key = xmlSecKeyPtr_get(key_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyInfoNodeWrite(keyInfoNode, key, keyInfoCtx)));
}

PyObject *xmlsec_KeyInfoCtxCreate(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxCreate", &mngr_obj))
    return NULL;

  if (mngr_obj != Py_None)
    mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  /* mngr may be NULL */
  keyInfoCtx = xmlSecKeyInfoCtxCreate(mngr);

  return (wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));
}

PyObject *xmlsec_KeyInfoCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxDestroy", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxDestroy(keyInfoCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *mngr_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeysMngrPtr mngr = NULL;

  if (!PyArg_ParseTuple(args, "OO:keyInfoCtxInitialize", &keyInfoCtx_obj, &mngr_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  /* mngr may be NULL */
  if (mngr_obj != Py_None)
    mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  
  return (wrap_int(xmlSecKeyInfoCtxInitialize(keyInfoCtx, mngr)));
}

PyObject *xmlsec_KeyInfoCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxFinalize", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxFinalize(keyInfoCtx);
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxReset(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxReset", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  xmlSecKeyInfoCtxReset(keyInfoCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxCopyUserPref(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecKeyInfoCtxPtr dst;
  xmlSecKeyInfoCtxPtr src;

  if (!PyArg_ParseTuple(args, "OO:keyInfoCtxCopyUserPref", &dst_obj, &src_obj))
    return NULL;

  dst = xmlSecKeyInfoCtxPtr_get(dst_obj);
  src = xmlSecKeyInfoCtxPtr_get(src_obj);

  return (wrap_int(xmlSecKeyInfoCtxCopyUserPref(dst, src)));
}

PyObject *xmlsec_KeyInfoCtxCreateEncCtx(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxCreateEncCtx", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyInfoCtxCreateEncCtx(keyInfoCtx)));
}

PyObject *xmlsec_KeyInfoCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *output_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  FILE *output;

  if (!PyArg_ParseTuple(args, "Os:keyInfoCtxDebugDump", &keyInfoCtx_obj, &output_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  output = PyFile_get(output_obj);
  xmlSecKeyInfoCtxDebugDump(keyInfoCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyInfoCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *output_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  FILE *output;

  if (!PyArg_ParseTuple(args, "Os:keyInfoCtxDebugXmlDump",
			&keyInfoCtx_obj, &output_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  output = PyFile_get(output_obj);
  xmlSecKeyInfoCtxDebugXmlDump(keyInfoCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataNameId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataNameId, NULL);
}
PyObject *xmlsec_KeyDataValueId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataValueId, NULL);
}
PyObject *xmlsec_KeyDataRetrievalMethodId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataRetrievalMethodId, NULL);
}
PyObject *xmlsec_KeyDataEncryptedKeyId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void  *)xmlSecKeyDataEncryptedKeyId, NULL);
}
