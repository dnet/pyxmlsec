/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software 
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "xmlsecmod.h"

#include "xmldsig.h"
#include "buffer.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysmngr.h"
#include "list.h"
#include "transforms.h"

PyObject *wrap_xmlSecDSigCtxPtr(xmlSecDSigCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecDSigReferenceCtxPtr(xmlSecDSigReferenceCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecDSigReferenceCtxPtr",
				     NULL);
  return (ret);
}

/******************************************************************************/
/* DSigCtx                                                                    */
/******************************************************************************/

PyObject *xmlSecDSigCtx_getattr(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  const char *attr;

  if (CheckArgs(args, "OS:dsigCtxGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:dsigCtxGetAttr", &dsigCtx_obj, &attr))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sssssssssssssssssssss]", "flags",
			 "flags2", "keyInfoReadCtx", "keyInfoWriteCtx",
			 "transformCtx", "enabledReferenceUris",
			 "enabledReferenceTransforms",
			 "defSignMethodId",
			 "defC14NMethodId", "defDigestMethodId",
			 "signKey", "operation", "result", "status",
			 "signMethod", "c14nMethod", "preSignMemBufMethod",
			 "signValueNode", "id", "signedInfoReferences",
			 "manifestReferences");
  if (!strcmp(attr, "flags")) return (wrap_int(dsigCtx->flags));
  if (!strcmp(attr, "flags2")) return (wrap_int(dsigCtx->flags2));
  if (!strcmp(attr, "keyInfoReadCtx"))
    return (wrap_xmlSecKeyInfoCtxPtr(&(dsigCtx->keyInfoReadCtx)));
  if (!strcmp(attr, "keyInfoWriteCtx"))
    return (wrap_xmlSecKeyInfoCtxPtr(&(dsigCtx->keyInfoWriteCtx)));
  if (!strcmp(attr, "transformCtx"))
    return (wrap_xmlSecTransformCtxPtr(&(dsigCtx->transformCtx)));
  if (!strcmp(attr, "enabledReferenceUris"))
    return (wrap_int(dsigCtx->enabledReferenceUris));
  if (!strcmp(attr, "enabledReferenceTransforms"))
    return (wrap_xmlSecPtrListPtr(dsigCtx->enabledReferenceTransforms));
  if (!strcmp(attr, "defSignMethodId"))
    return (wrap_xmlSecTransformId(dsigCtx->defSignMethodId));
  if (!strcmp(attr, "defC14NMethodId"))
    return (wrap_xmlSecTransformId(dsigCtx->defC14NMethodId));
  if (!strcmp(attr, "defDigestMethodId"))
    return (wrap_xmlSecTransformId(dsigCtx->defDigestMethodId));
  if (!strcmp(attr, "signKey")) return (wrap_xmlSecKeyPtr(dsigCtx->signKey));
  if (!strcmp(attr, "operation")) return (wrap_int(dsigCtx->operation));
  if (!strcmp(attr, "result")) return (wrap_xmlSecBufferPtr(dsigCtx->result));
  if (!strcmp(attr, "status")) return (wrap_int(dsigCtx->status));
  if (!strcmp(attr, "signMethod"))
    return (wrap_xmlSecTransformPtr(dsigCtx->signMethod));
  if (!strcmp(attr, "c14nMethod"))
    return (wrap_xmlSecTransformPtr(dsigCtx->c14nMethod));
  if (!strcmp(attr, "preSignMemBufMethod"))
    return (wrap_xmlSecTransformPtr(dsigCtx->preSignMemBufMethod));
  if (!strcmp(attr, "signValueNode"))
    return (wrap_xmlNodePtr(dsigCtx->signValueNode));
  if (!strcmp(attr, "id")) return (wrap_xmlCharPtr(dsigCtx->id));
  if (!strcmp(attr, "signedInfoReferences"))
    return (wrap_xmlSecPtrListPtr(&(dsigCtx->signedInfoReferences)));
  if (!strcmp(attr, "manifestReferences"))
    return (wrap_xmlSecPtrListPtr(&(dsigCtx->manifestReferences)));
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecDSigCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *value_obj;
  xmlSecDSigCtxPtr dsigCtx;
  const char *name;

  if (CheckArgs(args, "OS?:dsigCtxSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:dsigCtxSetAttr",
			  &dsigCtx_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
    
  if (!strcmp(name, "flags"))
    dsigCtx->flags = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "flags2"))
    dsigCtx->flags2 = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keyInfoReadCtx"))
    dsigCtx->keyInfoReadCtx = *(xmlSecKeyInfoCtxPtr_get(value_obj));
  else if (!strcmp(name, "keyInfoWriteCtx"))
    dsigCtx->keyInfoWriteCtx = *(xmlSecKeyInfoCtxPtr_get(value_obj));
  else if (!strcmp(name, "transformCtx"))
    dsigCtx->transformCtx = *(xmlSecTransformCtxPtr_get(value_obj));
  else if (!strcmp(name, "enabledReferenceUris"))
    dsigCtx->enabledReferenceUris = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "enabledReferenceTransforms"))
    dsigCtx->enabledReferenceTransforms = xmlSecPtrListPtr_get(value_obj);
  else if (!strcmp(name, "defSignMethodId"))
    dsigCtx->defSignMethodId = xmlSecTransformId_get(value_obj);
  else if (!strcmp(name, "defC14NMethodId"))
    dsigCtx->defC14NMethodId = xmlSecTransformId_get(value_obj);
  else if (!strcmp(name, "defDigestMethodId"))
    dsigCtx->defDigestMethodId = xmlSecTransformId_get(value_obj);
  else if (!strcmp(name, "signKey"))
    dsigCtx->signKey = xmlSecKeyPtr_get(value_obj);
  else if (!strcmp(name, "operation"))
    dsigCtx->operation = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "result"))
    dsigCtx->result = xmlSecBufferPtr_get(value_obj);
  else if (!strcmp(name, "status"))
    dsigCtx->status = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "signMethod"))
    dsigCtx->signMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "c14nMethod"))
    dsigCtx->c14nMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "preSignMemBufMethod"))
    dsigCtx->preSignMemBufMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "signValueNode"))
    dsigCtx->signValueNode = xmlNodePtr_get(value_obj);
  else if (!strcmp(name, "id"))
    dsigCtx->id = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "signedInfoReferences"))
    dsigCtx->signedInfoReferences = *(xmlSecPtrListPtr_get(value_obj));
  else if (!strcmp(name, "manifestReferences"))
    dsigCtx->manifestReferences = *(xmlSecPtrListPtr_get(value_obj));

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_DSigCtxCreate(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecDSigCtxPtr dsigCtx;
  
  if (CheckArgs(args, "o:dsigCtxCreate")) {
    if(!PyArg_ParseTuple(args, (char *) "O:dsigCtxCreate", &mngr_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  
  return (wrap_xmlSecDSigCtxPtr(dsigCtx));
}

PyObject *xmlsec_DSigCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (CheckArgs(args, "O:dsigCtxDestroy")) {
    if (!PyArg_ParseTuple(args, "O:dsigCtxDestroy", &dsigCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  xmlSecDSigCtxDestroy(dsigCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *mngr_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecKeysMngrPtr mngr = NULL;

  if (CheckArgs(args, "Oo:dsigCtxInitialize")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxInitialize", &dsigCtx_obj,
			  &mngr_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  
  return (wrap_int(xmlSecDSigCtxInitialize(dsigCtx, mngr)));
}

PyObject *xmlsec_DSigCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (CheckArgs(args, "O:dsigCtxFinalize")) {
    if (!PyArg_ParseTuple(args, "O:dsigCtxFinalize", &dsigCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  
  xmlSecDSigCtxFinalize(dsigCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *tmpl_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlNodePtr tmpl;

  if (CheckArgs(args, "OO:dsigCtxSign")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxSign", &dsigCtx_obj, &tmpl_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  tmpl = xmlNodePtr_get(tmpl_obj);

  return (wrap_int(xmlSecDSigCtxSign(dsigCtx, tmpl)));
}

PyObject *xmlsec_DSigCtxVerify(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *node_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlNodePtr node;

  if (CheckArgs(args, "OO:dsigCtxVerify")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxVerify", &dsigCtx_obj, &node_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecDSigCtxVerify(dsigCtx, node)));
}

PyObject *xmlsec_DSigCtxEnableReferenceTransform(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *transformId_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecTransformId transformId;
  int ret;

  if (CheckArgs(args, "OO:dsigCtxEnableReferenceTransform")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxEnableReferenceTransform",
			  &dsigCtx_obj, &transformId_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  transformId = xmlSecTransformId_get(transformId_obj);
  ret = xmlSecDSigCtxEnableReferenceTransform(dsigCtx, transformId);

  return (wrap_int(ret));
}

PyObject *xmlsec_DSigCtxEnableSignatureTransform(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *transformId_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecTransformId transformId;
  int ret;

  if (CheckArgs(args, "OO:dsigCtxEnableSignatureTransform")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxEnableSignatureTransform",
			  &dsigCtx_obj, &transformId_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  transformId = xmlSecTransformId_get(transformId_obj);
  ret = xmlSecDSigCtxEnableSignatureTransform(dsigCtx, transformId);

  return (wrap_int(ret));
}

PyObject *xmlsec_DSigCtxGetPreSignBuffer(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:dsigCtxGetPreSignBuffer")) {
    if (!PyArg_ParseTuple(args, "O:dsigCtxGetPreSignBuffer", &dsigCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  buf = xmlSecDSigCtxGetPreSignBuffer(dsigCtx);

  return (wrap_xmlSecBufferPtr(buf));
}

PyObject *xmlsec_DSigCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *output_obj;
  FILE *output;
  xmlSecDSigCtxPtr dsigCtx;

  if (CheckArgs(args, "OF:dsigCtxDebugDump")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxDebugDump", &dsigCtx_obj,
			  &output_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecDSigCtxDebugDump(dsigCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *output_obj;
  FILE *output;
  xmlSecDSigCtxPtr dsigCtx;

  if (CheckArgs(args, "OF:dsigCtxDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "OO:dsigCtxDebugXmlDump", &dsigCtx_obj,
			  &output_obj))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecDSigCtxDebugXmlDump(dsigCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

/*******************************************************************************/
/* DSigCtxReference                                                            */
/*******************************************************************************/

PyObject *xmlSecDSigReferenceCtx_getattr(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  const char *attr;

  if (CheckArgs(args, "OS:dsigReferenceCtxGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:dsigReferenceCtxGetAttr",
			  &dsigRefCtx_obj, &attr))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssssssss]", "dsigCtx",
			 "origin", "transformCtx", "digestMethod",
			 "result", "status", "preDigestMemBufMethod",
			 "id", "uri", "type");
  if (!strcmp(attr, "dsigCtx"))
    return (wrap_xmlSecDSigCtxPtr(dsigRefCtx->dsigCtx));
  if (!strcmp(attr, "origin")) return (wrap_int(dsigRefCtx->origin));
  if (!strcmp(attr, "transformCtx"))
    return (wrap_xmlSecTransformCtxPtr(&(dsigRefCtx->transformCtx)));
  if (!strcmp(attr, "digestMethod"))
    return (wrap_xmlSecTransformPtr(dsigRefCtx->digestMethod));
  if (!strcmp(attr, "result")) return (wrap_xmlSecBufferPtr(dsigRefCtx->result));
  if (!strcmp(attr, "status")) return (wrap_int((dsigRefCtx->status)));
  if (!strcmp(attr, "preDigestMemBufMethod"))
    return (wrap_xmlSecTransformPtr((dsigRefCtx->preDigestMemBufMethod)));
  if (!strcmp(attr, "id")) return (wrap_xmlCharPtr((dsigRefCtx->id)));
  if (!strcmp(attr, "uri")) return (wrap_xmlCharPtr((dsigRefCtx->uri)));
  if (!strcmp(attr, "type")) return (wrap_xmlCharPtr((dsigRefCtx->type)));
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecDSigReferenceCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *value_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  const char *name;

  if (CheckArgs(args, "OS?:dsigReferenceCtxSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:dsigReferenceCtxSetAttr",
			  &dsigRefCtx_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
    
  if (!strcmp(name, "dsigCtx"))
    dsigRefCtx->dsigCtx = xmlSecDSigCtxPtr_get(value_obj);
  else if (!strcmp(name, "origin"))
    dsigRefCtx->origin = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "transformCtx"))
    dsigRefCtx->transformCtx = *(xmlSecTransformCtxPtr_get(value_obj));
  else if (!strcmp(name, "digestMethod"))
    dsigRefCtx->digestMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "result"))
    dsigRefCtx->result = xmlSecBufferPtr_get(value_obj);
  else if (!strcmp(name, "status"))
    dsigRefCtx->status = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "preDigestMemBufMethod"))
    dsigRefCtx->preDigestMemBufMethod = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "id"))
    dsigRefCtx->id = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "uri"))
    dsigRefCtx->uri = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "type"))
    dsigRefCtx->type = (xmlChar *)PyString_AsString(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/*******************************************************************************/

PyObject *xmlsec_DSigReferenceCtxCreate(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigReferenceOrigin origin;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  
  if (CheckArgs(args, "OI:dsigReferenceCtxCreate")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:dsigReferenceCtxCreate",
			 &dsigCtx_obj, &origin))
      return NULL;
  }
  else return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  dsigRefCtx = xmlSecDSigReferenceCtxCreate(dsigCtx, origin);

  return (wrap_xmlSecDSigReferenceCtxPtr(dsigRefCtx));
}

PyObject *xmlsec_DSigReferenceCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  
  if (CheckArgs(args, "O:dsigReferenceCtxDestroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxDestroy",
			 &dsigRefCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  xmlSecDSigReferenceCtxDestroy(dsigRefCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigReferenceCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *dsigCtx_obj;
  xmlSecDSigReferenceOrigin origin;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlSecDSigCtxPtr dsigCtx;
  int ret;
  
  if (CheckArgs(args, "OOI:dsigReferenceCtxInitialize")) {
    if(!PyArg_ParseTuple(args, (char *) "OOi:dsigReferenceCtxInitialize",
			 &dsigRefCtx_obj, &dsigCtx_obj, &origin))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  dsigCtx = xmlSecDSigCtxPtr_get(dsigCtx_obj);
  ret = xmlSecDSigReferenceCtxInitialize(dsigRefCtx, dsigCtx, origin);

  return (wrap_int(ret));
}

PyObject *xmlsec_DSigReferenceCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  
  if (CheckArgs(args, "O:dsigReferenceCtxFinalize")) {
    if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxFinalize",
			 &dsigRefCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  xmlSecDSigReferenceCtxFinalize(dsigRefCtx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigReferenceCtxProcessNode(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *node_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlNodePtr node;
  
  if (CheckArgs(args, "OO:dsigReferenceCtxProcessNode")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:dsigReferenceCtxProcessNode",
			 &dsigRefCtx_obj, &node_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecDSigReferenceCtxProcessNode(dsigRefCtx, node)));
}

PyObject *xmlsec_DSigReferenceCtxGetPreDigestBuffer(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlSecBufferPtr buf;
  
  if (CheckArgs(args, "O:dsigReferenceCtxGetPreDigestBuffer")) {
    if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxGetPreDigestBuffer",
			 &dsigRefCtx_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  buf = xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx);

  return (wrap_xmlSecBufferPtr(buf));
}

PyObject *xmlsec_DSigReferenceCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *output_obj;
  FILE *output;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;

  if (CheckArgs(args, "OF:dsigReferenceCtxDebugDump")) {
    if (!PyArg_ParseTuple(args, "OO:dsigReferenceCtxDebugDump",
			  &dsigRefCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecDSigReferenceCtxDebugDump(dsigRefCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigReferenceCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *output_obj;
  FILE *output;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;

  if (CheckArgs(args, "OF:dsigReferenceCtxDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "OO:dsigReferenceCtxDebugXmlDump",
			  &dsigRefCtx_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(dsigRefCtx_obj);
  output = PythonFile_get(output_obj);
  xmlSecDSigReferenceCtxDebugXmlDump(dsigRefCtx, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_DSigReferenceCtxListId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecPtrListId(xmlSecDSigReferenceCtxListId));
}
