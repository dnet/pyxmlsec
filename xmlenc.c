/* $Id$ 
 *
 * pyxmlsec -- A Python binding for the XML Security library (XMLSec)
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

#include "xmlsecmod.h"
#include "keys.h"
#include "keysmngr.h"
#include "xmlenc.h"

PyObject *xmlsec_EncCtxCreate(PyObject *self, PyObject *args) {
  PyObject *keysMngr_obj;
  xmlSecKeysMngrPtr keysMngr = NULL;
  xmlSecEncCtxPtr encCtx;
  PyObject *ret = NULL;

  if (!PyArg_ParseTuple(args, "O:encCtxCreate", &keysMngr_obj))
    return NULL;

  if (keysMngr_obj != Py_None) {
    keysMngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(keysMngr_obj, PyString_FromString("_o")));
  }
  encCtx = xmlSecEncCtxCreate(keysMngr);
  ret = PyCObject_FromVoidPtrAndDesc((void *) encCtx, (char *) "xmlSecEncCtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_EncCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxDestroy", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  xmlSecEncCtxDestroy(encCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_EncCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *keysMngr_obj;
  xmlSecEncCtxPtr encCtx;
  xmlSecKeysMngrPtr keysMngr = NULL;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:encCtxInitialize", &encCtx_obj, &keysMngr_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  keysMngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(keysMngr_obj, PyString_FromString("_o")));
  
  ret = xmlSecEncCtxInitialize(encCtx, keysMngr);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxFinalize", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  
  xmlSecEncCtxFinalize(encCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_EncCtxCopyUserPref(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecEncCtxPtr dst, src;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:encCtxCopyUserPref", &dst_obj, &src_obj))
    return NULL;

  dst = xmlSecEncCtxPtr_get(PyObject_GetAttr(dst_obj, PyString_FromString("_o")));
  src = xmlSecEncCtxPtr_get(PyObject_GetAttr(src_obj, PyString_FromString("_o")));

  ret = xmlSecEncCtxCopyUserPref(dst, src);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxReset(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxReset", &encCtx_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  
  xmlSecEncCtxReset(encCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_EncCtxBinaryEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl;
  const xmlSecByte *data;
  xmlSecSize dataSize;
  int ret;

  if (!PyArg_ParseTuple(args, "OOsi:encCtxBinaryEncrypt", &encCtx_obj, &tmpl_obj,
			&data, &dataSize))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  tmpl = xmlNodePtr_get(PyObject_GetAttr(tmpl_obj, PyString_FromString("_o")));

  ret = xmlSecEncCtxBinaryEncrypt(encCtx, tmpl, data, dataSize);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxXmlEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl, node;
  int ret;

  if (!PyArg_ParseTuple(args, "OOO:encCtxXmlEncrypt", &encCtx_obj, &tmpl_obj,
			&node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  tmpl = xmlNodePtr_get(PyObject_GetAttr(tmpl_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  ret = xmlSecEncCtxXmlEncrypt(encCtx, tmpl, node);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxUriEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl;
  const xmlChar *uri;
  int ret;

  if (!PyArg_ParseTuple(args, "OOs:encCtxUriEncrypt", &encCtx_obj, &tmpl_obj,
			&uri))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  tmpl = xmlNodePtr_get(PyObject_GetAttr(tmpl_obj, PyString_FromString("_o")));

  ret = xmlSecEncCtxUriEncrypt(encCtx, tmpl, uri);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxDecrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:encCtxDecrypt", &encCtx_obj, &node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  ret = xmlSecEncCtxDecrypt(encCtx, node);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_EncCtxDecryptToBuffer(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;
  xmlSecBufferPtr buf;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OO:encCtxDecryptToBuffer", &encCtx_obj, &node_obj))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  buf = xmlSecEncCtxDecryptToBuffer(encCtx, node);
  if (buf == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) buf, (char *) "xmlSecBufferPtr", NULL);
  return (ret);
}

PyObject *xmlsec_EncCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "Os:encCtxDebugDump", &encCtx_obj, &output_path))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecEncCtxDebugDump(encCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_EncCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "Os:encCtxDebugXmlDump", &encCtx_obj, &output_path))
    return NULL;

  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecEncCtxDebugXmlDump(encCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

/******************************************************************************/

PyObject *xmlenc_set_encKey(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *encKey_obj;
  xmlSecEncCtxPtr encCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OO:encCtxSetEncKey", &encCtx_obj, &encKey_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));
  encCtx->encKey = xmlSecKeyPtr_get(PyObject_GetAttr(encKey_obj, PyString_FromString("_o")));

  ret = PyCObject_FromVoidPtrAndDesc((void *) encCtx, (char *) "xmlSecEncCtxPtr", NULL);
  return (ret);
}

PyObject *xmlenc_get_result(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResult", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));

  ret = PyCObject_FromVoidPtrAndDesc((void *) encCtx->result, (char *) "xmlSecBufferPtr", NULL);
  return (ret);
}

PyObject *xmlenc_get_resultBase64Encoded(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResultBase64Encoded", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", encCtx->resultBase64Encoded);
}

PyObject *xmlenc_get_resultReplaced(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (!PyArg_ParseTuple(args, "O:encCtxGetResultReplaced", &encCtx_obj))
    return NULL;
  encCtx = xmlSecEncCtxPtr_get(PyObject_GetAttr(encCtx_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", encCtx->resultReplaced);
}
