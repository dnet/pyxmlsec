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

/*****************************************************************************/

PyObject *keyinfo_get_enabledKeyData(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecPtrListPtr enabledKeyData;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxGetEnabledKeyData", &keyInfoCtx_obj))
    return NULL;
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  enabledKeyData = &(keyInfoCtx->enabledKeyData);

  ret = PyCObject_FromVoidPtrAndDesc((void *) enabledKeyData, (char *) "xmlSecPtrListPtr", NULL);
  return (ret);
}
