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

  if (CheckArgs(args, "II:base64CtxCreate")) {
    if (!PyArg_ParseTuple(args, "ii:base64CtxCreate", &encode, &columns))
      return NULL;
  }
  else return NULL;

  return (wrap_xmlSecBase64CtxPtr(xmlSecBase64CtxCreate(encode, columns)));
}

PyObject *xmlsec_Base64CtxDestroy(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (CheckArgs(args, "O:base64CtxDestroy")) {
    if (!PyArg_ParseTuple(args, "O:base64CtxDestroy", &ctx_obj))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OII:base64CtxInitialize")) {
    if (!PyArg_ParseTuple(args, "Oii:base64CtxInitialize",
			  &ctx_obj, &encode, &columns))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxInitialize(ctx, encode, columns)));
}

PyObject *xmlsec_Base64CtxFinalize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;

  if (CheckArgs(args, "O:base64CtxFinalize")) {
    if (!PyArg_ParseTuple(args, "O:base64CtxFinalize", &ctx_obj))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);
  
  xmlSecBase64CtxFinalize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

/* FIXME */
PyObject *xmlsec_Base64CtxUpdate(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;
  const xmlSecByte *in;
  xmlSecSize inSize;
  xmlSecByte *out;
  xmlSecSize outSize;

  if (CheckArgs(args, "OSISI:base64CtxUpdate")) {
    if (!PyArg_ParseTuple(args, "Osisi:base64CtxUpdate", &ctx_obj,
			  &in, &inSize, &out, &outSize))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxUpdate(ctx, in, inSize, out, outSize)));
}

/* FIXME */
PyObject *xmlsec_Base64CtxFinal(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecBase64CtxPtr ctx;
  xmlSecByte *out;
  xmlSecSize outSize;

  if (CheckArgs(args, "OSI:base64CtxFinal")) {
    if (!PyArg_ParseTuple(args, "Osi:base64CtxFinal",
			  &ctx_obj, &out, &outSize))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecBase64CtxPtr_get(ctx_obj);

  return (wrap_int(xmlSecBase64CtxFinal(ctx, out, outSize)));
}

PyObject *xmlsec_Base64Encode(PyObject *self, PyObject *args) {
  const xmlSecByte *buf;
  xmlSecSize len;
  int columns;
  xmlChar *strEnc;

  if (CheckArgs(args, "SII:base64Encode")) {
    if (!PyArg_ParseTuple(args, "sii:base64Encode", &buf, &len, &columns))
      return NULL;
  }
  else return NULL;

  strEnc = xmlSecBase64Encode(buf, len, columns);

  if (strEnc != NULL)
    return (PyString_FromStringAndSize((char *)strEnc, strlen((const char *)strEnc)));
  else {
    Py_INCREF(Py_None);
    return (Py_None);
  }
}

PyObject *xmlsec_Base64Decode(PyObject *self, PyObject *args) {
  const xmlChar* strEnc;
  xmlSecByte *strDec;
  xmlSecSize len;
  PyObject *ret = NULL;

  if (CheckArgs(args, "S:base64Decode")) {
    if (!PyArg_ParseTuple(args, "s:base64Decode", &strEnc))
      return NULL;
  }
  else return NULL;

  strDec = (xmlSecByte *) xmlMalloc(strlen((const char *)strEnc) * 2);

  len = xmlSecBase64Decode(strEnc, strDec, strlen((const char *)strEnc) * 2);

  if (len >= 0 && strDec != NULL)
    ret = PyString_FromStringAndSize((char *)strDec, len);
  else {
    Py_INCREF(Py_None);
    ret = Py_None;
  }

  xmlFree(strDec);
  return (ret);
}
