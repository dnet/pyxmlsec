/* $Id$ 
 *
 * PyXMLSec - Python bindings for the XML Security library (XMLSec)
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

#include "buffer.h"
#include "keys.h"
#include "keysmngr.h"
#include "xmlenc.h"

PyObject *wrap_xmlSecEncCtxPtr(xmlSecEncCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecEncCtxPtr", NULL);
  return (ret);
}

/*****************************************************************************/

PyObject *xmlsec_EncCtxCreate(PyObject *self, PyObject *args) {
  PyObject *keysMngr_obj;
  xmlSecKeysMngrPtr keysMngr = NULL;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxCreate", &keysMngr_obj))
    return NULL;

  if (keysMngr_obj != Py_None) {
    keysMngr = xmlSecKeysMngrPtr_get(keysMngr_obj);
  }
  encCtx = xmlSecEncCtxCreate(keysMngr);
  return (wrap_xmlSecEncCtxPtr(encCtx));
}

PyObject *xmlsec_EncCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxDestroy", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  xmlSecEncCtxDestroy(encCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *keysMngr_obj;
  xmlSecEncCtxPtr encCtx;
  xmlSecKeysMngrPtr keysMngr = NULL;

  if (!PyArg_ParseTuple(args, "OO:encCtxInitialize", &encCtx_obj, &keysMngr_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  keysMngr = xmlSecKeysMngrPtr_get(keysMngr_obj);
  
  return (wrap_int(xmlSecEncCtxInitialize(encCtx, keysMngr)));
}

PyObject *xmlsec_EncCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxFinalize", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  
  xmlSecEncCtxFinalize(encCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxCopyUserPref(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecEncCtxPtr dst, src;

  if (!PyArg_ParseTuple(args, "OO:encCtxCopyUserPref", &dst_obj, &src_obj))
    return NULL;

  dst = xmlSecEncCtxPtr_get(dst_obj);
  src = xmlSecEncCtxPtr_get(src_obj);

  return (wrap_int(xmlSecEncCtxCopyUserPref(dst, src)));
}

PyObject *xmlsec_EncCtxReset(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxReset", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  
  xmlSecEncCtxReset(encCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxBinaryEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl;
  const xmlSecByte *data;
  xmlSecSize dataSize;

  if (!PyArg_ParseTuple(args, "OOsi:encCtxBinaryEncrypt", &encCtx_obj, &tmpl_obj,
			&data, &dataSize))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);

  return (wrap_int(xmlSecEncCtxBinaryEncrypt(encCtx, tmpl, data, dataSize)));
}

PyObject *xmlsec_EncCtxXmlEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl, node;

  if (!PyArg_ParseTuple(args, "OOO:encCtxXmlEncrypt", &encCtx_obj, &tmpl_obj,
			&node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecEncCtxXmlEncrypt(encCtx, tmpl, node)));
}

PyObject *xmlsec_EncCtxUriEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl;
  const xmlChar *uri;

  if (!PyArg_ParseTuple(args, "OOs:encCtxUriEncrypt", &encCtx_obj, &tmpl_obj,
			&uri))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);

  return (wrap_int(xmlSecEncCtxUriEncrypt(encCtx, tmpl, uri)));
}

PyObject *xmlsec_EncCtxDecrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, "OO:encCtxDecrypt", &encCtx_obj, &node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecEncCtxDecrypt(encCtx, node)));
}

PyObject *xmlsec_EncCtxDecryptToBuffer(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;
  xmlSecBufferPtr buf;

  if (!PyArg_ParseTuple(args, "OO:encCtxDecryptToBuffer", &encCtx_obj, &node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  node = xmlNodePtr_get(node_obj);

  buf = xmlSecEncCtxDecryptToBuffer(encCtx, node);
  if (buf == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  
  return (wrap_xmlSecBufferPtr(buf));
}

PyObject *xmlsec_EncCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *output_obj;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "Os:encCtxDebugDump", &encCtx_obj, &output_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  output = PyFile_get(output_obj);
  xmlSecEncCtxDebugDump(encCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *output_obj;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "Os:encCtxDebugXmlDump", &encCtx_obj, &output_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  output = PyFile_get(output_obj);
  xmlSecEncCtxDebugXmlDump(encCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlenc_set_encKey(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *encKey_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "OO:encCtxSetEncKey", &encCtx_obj, &encKey_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  encCtx->encKey = xmlSecKeyPtr_get(encKey_obj);

  return (wrap_xmlSecEncCtxPtr(encCtx));
}

PyObject *xmlenc_get_result(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResult", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);

  return (wrap_xmlSecBufferPtr(encCtx->result));
}

PyObject *xmlenc_get_resultBase64Encoded(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResultBase64Encoded", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);

  return (wrap_int(encCtx->resultBase64Encoded));
}

PyObject *xmlenc_get_resultReplaced(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResultReplaced", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);

  return (wrap_int(encCtx->resultReplaced));
}
