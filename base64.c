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

#include "base64.h"

PyObject *wrap_xmlSecBase64CtxPtr(xmlSecBase64CtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecBase64CtxPtr", NULL);
  return (ret);
}

/*****************************************************************************/

PyObject *xmlsec_Base64CtxCreate(PyObject *self, PyObject *args) {
  int encode;
  int columns;

  if (!PyArg_ParseTuple(args, "ii:base64CtxCreate", &encode, &columns))
    return NULL;

  return (wrap_xmlSecBase64CtxPtr(xmlSecBase64CtxCreate(encode, columns)));
}

PyObject *xmlsec_Base64CtxDestroy(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (!PyArg_ParseTuple(args, "O:base64CtxDestroy", &ctx_obj))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);
  
  xmlSecBase64CtxDestroy(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_Base64CtxInitialize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  int encode;
  int columns;
  xmlSecBase64CtxPtr ctx;

  if (!PyArg_ParseTuple(args, "Oii:base64CtxInitialize",
			&ctx_obj, &encode, &columns))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxInitialize(ctx, encode, columns)));
}

PyObject *xmlsec_Base64CtxFinalize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (!PyArg_ParseTuple(args, "O:base64CtxFinalize", &ctx_obj))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);
  
  xmlSecBase64CtxFinalize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_Base64CtxUpdate(PyObject *self, PyObject *args) {
  PyObject *ctx_obj, *out_obj;
  xmlSecBase64CtxPtr ctx;
  const xmlSecByte *in;
  xmlSecSize inSize;
  xmlSecSize outSize;

  if (!PyArg_ParseTuple(args, "OsiOi:base64CtxUpdate", &ctx_obj, &in, &inSize,
			&out_obj, &outSize))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxUpdate(ctx, in, inSize,
					 (xmlSecByte *)out_obj, outSize)));
}

PyObject *xmlsec_Base64CtxFinal(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;
  xmlSecByte *out;
  xmlSecSize outSize;

  if (!PyArg_ParseTuple(args, "Os#:base64CtxFinal",
			&ctx_obj, &out, &outSize))
    return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxFinal(ctx, out, outSize)));
}

PyObject *xmlsec_Base64Encode(PyObject *self, PyObject *args) {
  const xmlSecByte *buf;
  xmlSecSize len;
  int columns;

  if (!PyArg_ParseTuple(args, "sii:base64Encode", &buf, &len, &columns))
    return NULL;

  return (wrap_xmlCharPtr(xmlSecBase64Encode(buf, len, columns)));
}

PyObject *xmlsec_Base64Decode(PyObject *self, PyObject *args) {
  const xmlChar* str;
  xmlSecByte *buf;
  xmlSecSize len;

  if (!PyArg_ParseTuple(args, "ss#:base64Decode", &str, &buf, &len))
    return NULL;

  return (wrap_int(xmlSecBase64Decode(str, buf, len)));
}
