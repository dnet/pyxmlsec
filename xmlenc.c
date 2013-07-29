/* $Id$ 
 *
 * PyXMLSec - Python bindings for the XML Security library (XMLSec)
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

#include "xmlenc.h"
#include "buffer.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysmngr.h"
#include "transforms.h"

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

PyObject *xmlSecEncCtx_getattr(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;
  const char *attr;

  if (CheckArgs(args, "OS:encCtxGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:encCtxGetAttr",
			  &encCtx_obj, &attr))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sssssssssssssssssssssss]", "flags",
			 "flags2", "mode", "keyInfoReadCtx", "keyInfoWriteCtx",
			 "transformCtx", "defEncMethodId",
			 "encKey", "operation", "result", "resultBase64Encoded",
			 "resultReplaced", "encMethod",
			 "id", "type", "mimeType", "encoding", "recipient",
			 "carriedKeyName", "encDataNode", "encMethodNode",
			 "keyInfoNode", "cipherValueNode");
  if (!strcmp(attr, "flags"))
    return (wrap_int(encCtx->flags));
  if (!strcmp(attr, "flags2"))
    return (wrap_int(encCtx->flags2));
  if (!strcmp(attr, "mode"))
    return (wrap_int(encCtx->mode));
  if (!strcmp(attr, "keyInfoReadCtx"))
    return (wrap_xmlSecKeyInfoCtxPtr(&(encCtx->keyInfoReadCtx)));
  if (!strcmp(attr, "keyInfoWriteCtx"))
    return (wrap_xmlSecKeyInfoCtxPtr(&(encCtx->keyInfoWriteCtx)));
  if (!strcmp(attr, "transformCtx"))
    return (wrap_xmlSecTransformCtxPtr(&(encCtx->transformCtx)));
  if (!strcmp(attr, "defEncMethodId"))
    return (wrap_xmlSecTransformId(encCtx->defEncMethodId));
  if (!strcmp(attr, "encKey"))
    return (wrap_xmlSecKeyPtr(encCtx->encKey));
  if (!strcmp(attr, "operation"))
    return (wrap_int(encCtx->operation));
  if (!strcmp(attr, "result"))
    return (wrap_xmlSecBufferPtr(encCtx->result));
  if (!strcmp(attr, "resultBase64Encoded"))
    return (wrap_int(encCtx->resultBase64Encoded));
  if (!strcmp(attr, "resultReplaced"))
    return (wrap_int(encCtx->resultReplaced));
  if (!strcmp(attr, "encMethod"))
    return (wrap_xmlSecTransformPtr(encCtx->encMethod));
  if (!strcmp(attr, "id"))
    return (wrap_xmlCharPtr(encCtx->id));
  if (!strcmp(attr, "type"))
    return (wrap_xmlCharPtr(encCtx->type));
  if (!strcmp(attr, "mimeType"))
    return (wrap_xmlCharPtr(encCtx->mimeType));
  if (!strcmp(attr, "encoding"))
    return (wrap_xmlCharPtr(encCtx->encoding));
  if (!strcmp(attr, "recipient"))
    return (wrap_xmlCharPtr(encCtx->recipient));
  if (!strcmp(attr, "carriedKeyName"))
    return (wrap_xmlCharPtr(encCtx->carriedKeyName));
  if (!strcmp(attr, "encDataNode"))
    return (wrap_xmlNodePtr(encCtx->encDataNode));
  if (!strcmp(attr, "encMethodNode"))
    return (wrap_xmlNodePtr(encCtx->encMethodNode));
  if (!strcmp(attr, "keyInfoNode"))
    return (wrap_xmlNodePtr(encCtx->keyInfoNode));
  if (!strcmp(attr, "cipherValueNode"))
    return (wrap_xmlNodePtr(encCtx->cipherValueNode));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecEncCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *value_obj;
  xmlSecEncCtxPtr encCtx;
  const char *name;

  if (CheckArgs(args, "OSO:encCtxSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:encCtxSetAttr",
			  &encCtx_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
    
  if (!strcmp(name, "flags"))
    encCtx->flags = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "flags2"))
    encCtx->flags2 = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "mode"))
    encCtx->mode = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keyInfoReadCtx"))
    encCtx->keyInfoReadCtx = *(xmlSecKeyInfoCtxPtr_get(value_obj));
  else if (!strcmp(name, "keyInfoWriteCtx"))
    encCtx->keyInfoWriteCtx = *(xmlSecKeyInfoCtxPtr_get(value_obj));
  else if (!strcmp(name, "transformCtx"))
    encCtx->transformCtx = *(xmlSecTransformCtxPtr_get(value_obj));
  else if (!strcmp(name, "defEncMethodId"))
    encCtx->defEncMethodId = xmlSecTransformId_get(value_obj);
  else if (!strcmp(name, "encKey"))
    encCtx->encKey = xmlSecKeyPtr_get(value_obj);
  else if (!strcmp(name, "operation"))
    encCtx->operation = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "result"))
    encCtx->result = xmlSecBufferPtr_get(value_obj);
  else if (!strcmp(name, "resultBase64Encoded"))
    encCtx->resultBase64Encoded = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "resultReplaced"))
    encCtx->resultReplaced = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "encMethod"))
    encCtx->encMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "id"))
    encCtx->id = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "type"))
    encCtx->type = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "mimeType"))
    encCtx->mimeType = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "encoding"))
    encCtx->encoding = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "recipient"))
    encCtx->recipient = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "carriedKeyName"))
    encCtx->carriedKeyName = (xmlChar *)PyString_AsString(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_EncCtxCreate(PyObject *self, PyObject *args) {
  PyObject *keysMngr_obj;
  xmlSecKeysMngrPtr keysMngr = NULL;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "o:encCtxCreate")) {
    if (!PyArg_ParseTuple(args, "O:encCtxCreate", &keysMngr_obj))
      return NULL;
  }
  else return NULL;

  keysMngr = xmlSecKeysMngrPtr_get(keysMngr_obj);
  encCtx = xmlSecEncCtxCreate(keysMngr);

  return (wrap_xmlSecEncCtxPtr(encCtx));
}

PyObject *xmlsec_EncCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "O:encCtxDestroy")) {
    if (!PyArg_ParseTuple(args, "O:encCtxDestroy", &encCtx_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  xmlSecEncCtxDestroy(encCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *keysMngr_obj;
  xmlSecEncCtxPtr encCtx;
  xmlSecKeysMngrPtr keysMngr = NULL;

  if (CheckArgs(args, "Oo:encCtxInitialize")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxInitialize",
			  &encCtx_obj, &keysMngr_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  keysMngr = xmlSecKeysMngrPtr_get(keysMngr_obj);
  
  return (wrap_int(xmlSecEncCtxInitialize(encCtx, keysMngr)));
}

PyObject *xmlsec_EncCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "O:encCtxFinalize")) {
    if (!PyArg_ParseTuple(args, "O:encCtxFinalize", &encCtx_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  
  xmlSecEncCtxFinalize(encCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxCopyUserPref(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecEncCtxPtr dst, src;

  if (CheckArgs(args, "OO:encCtxCopyUserPref")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxCopyUserPref", &dst_obj, &src_obj))
      return NULL;
  }
  else return NULL;

  dst = xmlSecEncCtxPtr_get(dst_obj);
  src = xmlSecEncCtxPtr_get(src_obj);

  return (wrap_int(xmlSecEncCtxCopyUserPref(dst, src)));
}

PyObject *xmlsec_EncCtxReset(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "O:encCtxReset")) {
    if (!PyArg_ParseTuple(args, "O:encCtxReset", &encCtx_obj))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OOSI:encCtxBinaryEncrypt")) {
    if (!PyArg_ParseTuple(args, "OOsi:encCtxBinaryEncrypt",
			  &encCtx_obj, &tmpl_obj, &data, &dataSize))
    return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);

  return (wrap_int(xmlSecEncCtxBinaryEncrypt(encCtx, tmpl, data, dataSize)));
}

PyObject *xmlsec_EncCtxXmlEncrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *tmpl_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr tmpl, node;

  if (CheckArgs(args, "OOO:encCtxXmlEncrypt")) {
    if (!PyArg_ParseTuple(args, "OOO:encCtxXmlEncrypt", &encCtx_obj, &tmpl_obj,
			  &node_obj))
    return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OOS:encCtxUriEncrypt")) {
    if (!PyArg_ParseTuple(args, "OOs:encCtxUriEncrypt", &encCtx_obj, &tmpl_obj,
			  &uri))
    return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);

  return (wrap_int(xmlSecEncCtxUriEncrypt(encCtx, tmpl, uri)));
}

PyObject *xmlsec_EncCtxDecrypt(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;

  if (CheckArgs(args, "OO:encCtxDecrypt")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxDecrypt", &encCtx_obj, &node_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecEncCtxDecrypt(encCtx, node)));
}

PyObject *xmlsec_EncCtxDecryptToBuffer(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *node_obj;
  xmlSecEncCtxPtr encCtx;
  xmlNodePtr node;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "OO:encCtxDecryptToBuffer")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxDecryptToBuffer", &encCtx_obj, &node_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  node = xmlNodePtr_get(node_obj);

  buf = xmlSecEncCtxDecryptToBuffer(encCtx, node);
  
  return (wrap_xmlSecBufferPtr(buf));
}

PyObject *xmlsec_EncCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *output_obj;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "OF:encCtxDebugDump")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxDebugDump",
			  &encCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecEncCtxDebugDump(encCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_EncCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *encCtx_obj, *output_obj;
  FILE *output;
  xmlSecEncCtxPtr encCtx;

  if (CheckArgs(args, "OF:encCtxDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "OO:encCtxDebugXmlDump",
			  &encCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  encCtx = xmlSecEncCtxPtr_get(encCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecEncCtxDebugXmlDump(encCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}
