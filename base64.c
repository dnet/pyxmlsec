/* $Id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
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
#include "base64.h"

PyObject *xmlsec_Base64CtxCreate(PyObject *self, PyObject *args) {
  int encode;
  int columns;
  xmlSecBase64CtxPtr ctx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "ii:base64CtxCreate", &encode, &columns))
    return NULL;

  ctx = xmlSecBase64CtxCreate(encode, columns);
  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }

  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx, (char *) "xmlSecBase64CtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_Base64CtxDestroy(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (!PyArg_ParseTuple(args, "O:base64CtxDestroy", &ctx_obj))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(PyObject_GetAttr(ctx_obj, PyString_FromString("_o")));
  
  xmlSecBase64CtxDestroy(ctx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_Base64CtxInitialize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  int encode;
  int columns;
  xmlSecBase64CtxPtr ctx;
  int ret;

  if (!PyArg_ParseTuple(args, "Oii:base64CtxInitialize", &ctx_obj, &encode, &columns))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(PyObject_GetAttr(ctx_obj, PyString_FromString("_o")));

  ret = xmlSecBase64CtxInitialize(ctx, encode, columns);

  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_Base64CtxFinalize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (!PyArg_ParseTuple(args, "O:base64CtxFinalize", &ctx_obj))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(PyObject_GetAttr(ctx_obj, PyString_FromString("_o")));
  
  xmlSecBase64CtxFinalize(ctx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_Base64CtxUpdate(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;
  const xmlSecByte *in;
  xmlSecSize inSize;
  xmlSecByte *out;
  xmlSecSize outSize;
  int ret;

  if (!PyArg_ParseTuple(args, "Osisi:base64CtxUpdate", &ctx_obj, &in, &inSize,
			&out, &outSize))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(PyObject_GetAttr(ctx_obj, PyString_FromString("_o")));

  ret = xmlSecBase64CtxUpdate(ctx, in, inSize, out, outSize);

  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_Base64CtxFinal(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;
  xmlSecByte *out;
  xmlSecSize outSize;
  int ret;

  if (!PyArg_ParseTuple(args, "Osisi:base64CtxFinal", &ctx_obj, &out, &outSize))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(PyObject_GetAttr(ctx_obj, PyString_FromString("_o")));

  ret = xmlSecBase64CtxFinal(ctx, out, outSize);

  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_Base64Encode(PyObject *self, PyObject *args) {
  const xmlSecByte *buf;
  xmlSecSize len;
  int columns;
  xmlChar *ret;

  if (!PyArg_ParseTuple(args, "sii:base64Encode", &buf, &len, &columns))
    return NULL;

  ret = xmlSecBase64Encode(buf, len, columns);

  if (ret == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return Py_BuildValue("s", ret);
}

PyObject *xmlsec_Base64Decode(PyObject *self, PyObject *args) {
  const xmlChar* str;
  xmlSecByte *buf;
  xmlSecSize len;
  int ret;

  if (!PyArg_ParseTuple(args, "sii:base64Decode", &str, &buf, &len))
    return NULL;

  ret = xmlSecBase64Decode(str, buf, len);

  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}
