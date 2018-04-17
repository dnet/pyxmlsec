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

#include "transforms.h"
#include "buffer.h"
#include "keys.h"
#include "list.h"
#include "nodeset.h"

PyObject *wrap_xmlSecTransformCtxPtr(xmlSecTransformCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecTransformCtxPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecTransformPtr(xmlSecTransformPtr transform) {
  PyObject *ret;

  if (transform == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) transform,
				     (char *) "xmlSecTransformPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecTransformId(xmlSecTransformId transformId) {
  PyObject *ret;

  if (transformId == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) transformId,
				     (char *) "xmlSecTransformId", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *xmlsec_TransformUriTypeCheck(PyObject *self, PyObject *args) {
  xmlSecTransformUriType type;
  const xmlChar *uri;
  int ret;

  if (CheckArgs(args, "IS:transformUriTypeCheck")) {
    if(!PyArg_ParseTuple(args, (char *) "is:transformUriTypeCheck", &type, &uri))
      return NULL;
  }
  else return NULL;

  ret = xmlSecTransformUriTypeCheck(type, uri);
  return (wrap_int(ret));
}

/******************************************************************************/
/* TransformCtx                                                               */
/******************************************************************************/

static xmlHashTablePtr TransformCtxPreExecuteCallbacks = NULL;

static int xmlsec_TransformCtxPreExecuteCallback(xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformCtxPreExecuteCallbacks,
			transformCtx->uri, transformCtx->xptrExpr);

  args = Py_BuildValue((char *) "O", wrap_xmlSecTransformCtxPtr(transformCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

PyObject *xmlSecTransformCtx_getattr(PyObject *self, PyObject *args) {
  PyObject *transformCtx_obj;
  xmlSecTransformCtxPtr transformCtx;
  const char *attr;

  if (CheckArgs(args, "OS:transformCtxGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:transformCtxGetAttr",
			  &transformCtx_obj, &attr))
      return NULL;
  }
  else return NULL;

  transformCtx = xmlSecTransformCtxPtr_get(transformCtx_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sssssssssss]", "flags",
			 "flags2", "enabledUris", "enabledTransforms",
			 "preExecCallback", "result", "status", "uri",
			 "xptrExpr", "first", "last");
  if (!strcmp(attr, "flags"))
    return (wrap_int(transformCtx->flags));
  if (!strcmp(attr, "flags2"))
    return (wrap_int(transformCtx->flags2));
  if (!strcmp(attr, "enabledUris"))
    return (wrap_int(transformCtx->enabledUris));
  if (!strcmp(attr, "enabledTransforms"))
    return (wrap_xmlSecPtrListPtr(&(transformCtx->enabledTransforms)));
  if (!strcmp(attr, "preExecCallback"))
    return PyCObject_FromVoidPtr((void *) transformCtx->preExecCallback, NULL);
  if (!strcmp(attr, "result"))
    return (wrap_xmlSecBufferPtr(transformCtx->result));
  if (!strcmp(attr, "status"))
    return (wrap_int(transformCtx->status));
  if (!strcmp(attr, "uri"))
    return (wrap_xmlCharPtr(transformCtx->uri));
  if (!strcmp(attr, "xptrExpr"))
    return (wrap_xmlCharPtr(transformCtx->xptrExpr));
  if (!strcmp(attr, "first"))
    return (wrap_xmlSecTransformPtr(transformCtx->first));
  if (!strcmp(attr, "last"))
    return (wrap_xmlSecTransformPtr(transformCtx->last));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecTransformCtx_setattr(PyObject *self, PyObject *args) {
  PyObject *transformCtx_obj, *value_obj;
  xmlSecTransformCtxPtr transformCtx;
  const char *name;

  if (CheckArgs(args, "OS?:transformCtxSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:transformCtxSetAttr",
			  &transformCtx_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  transformCtx = xmlSecTransformCtxPtr_get(transformCtx_obj);
    
  if (!strcmp(name, "flags"))
    transformCtx->flags = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "flags2"))
    transformCtx->flags2 = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "enabledUris"))
    transformCtx->enabledUris = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "enabledTransforms"))
    transformCtx->enabledTransforms = *(xmlSecPtrListPtr_get(value_obj));
  else if (!strcmp(name, "preExecCallback"))
    if (value_obj != Py_None) {
      if (TransformCtxPreExecuteCallbacks == NULL)
	TransformCtxPreExecuteCallbacks = xmlHashCreate(HASH_TABLE_SIZE);
      xmlHashAddEntry2(TransformCtxPreExecuteCallbacks,
		       transformCtx->uri, transformCtx->xptrExpr, value_obj);
      Py_XINCREF(value_obj);
      transformCtx->preExecCallback = xmlsec_TransformCtxPreExecuteCallback;
    }
    else
      transformCtx->preExecCallback = NULL;
  else if (!strcmp(name, "result"))
    transformCtx->result = xmlSecBufferPtr_get(value_obj);
  else if (!strcmp(name, "status"))
    transformCtx->status = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "uri"))
    transformCtx->uri = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "xptrExpr"))
    transformCtx->xptrExpr = (xmlChar *)PyString_AsString(value_obj);
  else if (!strcmp(name, "first"))
    transformCtx->first = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "last"))
    transformCtx->last = xmlSecTransformPtr_get(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_TransformCtxCreate(PyObject *self, PyObject *args) {
  xmlSecTransformCtxPtr ctx;

  ctx = xmlSecTransformCtxCreate();

  return (wrap_xmlSecTransformCtxPtr(ctx));
}

PyObject *xmlsec_TransformCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if (CheckArgs(args, "O:transformCtxDestroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformCtxDestroy", &ctx_obj))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxDestroy(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if (CheckArgs(args, "O:transformCtxInitialize")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformCtxInitialize", &ctx_obj))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxInitialize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if (CheckArgs(args, "O:transformCtxFinalize")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformCtxFinalize", &ctx_obj))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxFinalize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxReset(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if (CheckArgs(args, "O:transformCtxReset")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformCtxReset", &ctx_obj))
      return NULL;
  }
  else return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxReset(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/
/* Transform                                                                  */
/******************************************************************************/

PyObject *xmlSecTransform_getattr(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  const char *attr;

  if (CheckArgs(args, "OS:transformGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:transformGetAttr",
			  &transform_obj, &attr))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssssssss]", "id", "operation", "status",
			 "hereNode", "next", "prev", "inBuf", "outBuf",
			 "inNodes", "outNodes");
  if (!strcmp(attr, "id"))
    return (wrap_xmlSecTransformId(transform->id));
  if (!strcmp(attr, "operation"))
    return (wrap_int(transform->operation));
  if (!strcmp(attr, "status"))
    return (wrap_int(transform->status));
  if (!strcmp(attr, "hereNode"))
    return (wrap_xmlNodePtr(transform->hereNode));
  if (!strcmp(attr, "next"))
    return (wrap_xmlSecTransformPtr(transform->next));
  if (!strcmp(attr, "prev"))
    return (wrap_xmlSecTransformPtr(transform->prev));
  if (!strcmp(attr, "inBuf"))
    return (wrap_xmlSecBufferPtr(&(transform->inBuf)));
  if (!strcmp(attr, "outBuf"))
    return (wrap_xmlSecBufferPtr(&(transform->outBuf)));
  if (!strcmp(attr, "inNodes"))
    return (wrap_xmlSecNodeSetPtr(transform->inNodes));
  if (!strcmp(attr, "outNodes"))
    return (wrap_xmlSecNodeSetPtr(transform->outNodes));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecTransform_setattr(PyObject *self, PyObject *args) {
  PyObject *transform_obj, *value_obj;
  xmlSecTransformPtr transform;
  const char *name;

  if (CheckArgs(args, "OS?:transformSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:transformSetAttr",
			  &transform_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
    
  if (!strcmp(name, "id"))
    transform->id = xmlSecTransformId_get(value_obj);
  else if (!strcmp(name, "operation"))
    transform->operation = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "status"))
    transform->status = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "hereNode"))
    transform->hereNode = xmlNodePtr_get(value_obj);
  else if (!strcmp(name, "next"))
    transform->next = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "prev"))
    transform->prev = xmlSecTransformPtr_get(value_obj);
  else if (!strcmp(name, "inBuf"))
    transform->inBuf = *(xmlSecBufferPtr_get(value_obj));
  else if (!strcmp(name, "outBuf"))
    transform->outBuf = *(xmlSecBufferPtr_get(value_obj));
  else if (!strcmp(name, "inNodes"))
    transform->inNodes = xmlSecNodeSetPtr_get(value_obj);
  else if (!strcmp(name, "outNodes"))
    transform->outNodes = xmlSecNodeSetPtr_get(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_TransformCreate(PyObject *self, PyObject *args) {
  PyObject *id_obj;
  xmlSecTransformId id;
  xmlSecTransformPtr transform;

  if (CheckArgs(args, "O:transformCreate")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformCreate", &id_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecTransformId_get(id_obj);
  transform = xmlSecTransformCreate(id);

  return (wrap_xmlSecTransformPtr(transform));
}

PyObject *xmlsec_TransformDestroy(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;

  if (CheckArgs(args, "O:transformDestroy")) {
    if(!PyArg_ParseTuple(args, (char *) "O:transformDestroy", &transform_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  xmlSecTransformDestroy(transform);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformNodeRead(PyObject *self, PyObject *args) {
  PyObject *node_obj, *transformCtx_obj;
  xmlNodePtr node;
  xmlSecTransformUsage usage;
  xmlSecTransformCtxPtr transformCtx;
  xmlSecTransformPtr transform;

  if (CheckArgs(args, "OIO:transformNodeRead")) {
    if(!PyArg_ParseTuple(args, (char *) "OiO:transformNodeRead", &node_obj,
			 &usage, &transformCtx_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);
  transformCtx = xmlSecTransformCtxPtr_get(transformCtx_obj);
  transform = xmlSecTransformNodeRead(node, usage, transformCtx);

  return (wrap_xmlSecTransformPtr(transform));
}

PyObject *xmlsec_TransformSetKey(PyObject *self, PyObject *args) {
  PyObject *transform_obj, *key_obj;
  xmlSecTransformPtr transform;
  xmlSecKeyPtr key;
  int ret;

  if (CheckArgs(args, "OO:transformSetKey")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:transformSetKey", &transform_obj,
			 &key_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  key = xmlSecKeyPtr_get(key_obj);
  ret = xmlSecTransformSetKey(transform, key);

  return (wrap_int(ret));
}

PyObject *xmlsec_TransformSetKeyReq(PyObject *self, PyObject *args) {
  PyObject *transform_obj, *keyReq_obj;
  xmlSecTransformPtr transform;
  xmlSecKeyReqPtr keyReq;
  int ret;

  if (CheckArgs(args, "OO:transformSetKeyReq")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:transformSetKeyReq",
			 &transform_obj, &keyReq_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  ret = xmlSecTransformSetKeyReq(transform, keyReq);

  return (wrap_int(ret));
}

PyObject *xmlsec_TransformBase64SetLineSize(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  xmlSecSize lineSize;

  if (CheckArgs(args, "OI:transformBase64SetLineSize")) {
    if(!PyArg_ParseTuple(args, (char *) "Oi:transformBase64SetLineSize",
			 &transform_obj, &lineSize))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  xmlSecTransformBase64SetLineSize(transform, lineSize);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformXPointerSetExpr(PyObject *self, PyObject *args) {
  PyObject *transform_obj, *hereNode_obj;
  xmlSecTransformPtr transform;
  const xmlChar *expr;
  xmlSecNodeSetType nodeSetType;
  xmlNodePtr hereNode;
  int ret;

  if (CheckArgs(args, "OSIO:transformXPointerSetExpr")) {
    if(!PyArg_ParseTuple(args, (char *) "OsiO:transformXPointerSetExpr",
			 &transform_obj, &expr, &nodeSetType, &hereNode_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  hereNode = xmlNodePtr_get(hereNode_obj);
  ret = xmlSecTransformXPointerSetExpr(transform, expr, nodeSetType, hereNode);

  return (wrap_int(ret));
}

PyObject *xmlsec_TransformVisa3DHackSetID(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  const xmlChar *id;
  int ret;

  if (CheckArgs(args, "OS:transformVisa3DHackSetID")) {
    if(!PyArg_ParseTuple(args, (char *) "Os:transformVisa3DHackSetID",
			 &transform_obj, &id))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  ret = xmlSecTransformVisa3DHackSetID(transform, id);

  return (wrap_int(ret));
}

/*****************************************************************************/

PyObject *xmlsec_TransformBase64Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformBase64Id, NULL);
}

PyObject *xmlsec_TransformInclC14NId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformInclC14NId, NULL);
}

PyObject *xmlsec_TransformInclC14NWithCommentsId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformInclC14NWithCommentsId, NULL);
}

PyObject *xmlsec_TransformExclC14NId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformExclC14NId, NULL);
}

PyObject *xmlsec_TransformExclC14NWithCommentsId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformExclC14NWithCommentsId, NULL);
}

PyObject *xmlsec_TransformEnvelopedId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformEnvelopedId, NULL);
}

PyObject *xmlsec_TransformXPathId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformXPathId, NULL);
}

PyObject *xmlsec_TransformXPath2Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformXPath2Id, NULL);
}

PyObject *xmlsec_TransformXPointerId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformXPointerId, NULL);
}

PyObject *xmlsec_TransformXsltId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformXsltId, NULL);
}

PyObject *xmlsec_TransformRemoveXmlTagsC14NId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformRemoveXmlTagsC14NId, NULL);
}

PyObject *xmlsec_TransformVisa3DHackId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformVisa3DHackId, NULL);
}

/******************************************************************************/
/* TransformId                                                                */
/******************************************************************************/

static xmlHashTablePtr TransformInitializeMethods = NULL;
static xmlHashTablePtr TransformFinalizeMethods = NULL;
static xmlHashTablePtr TransformNodeReadMethods = NULL;
static xmlHashTablePtr TransformNodeWriteMethods = NULL;
static xmlHashTablePtr TransformSetKeyRequirementsMethods = NULL;
static xmlHashTablePtr TransformSetKeyMethods = NULL;
static xmlHashTablePtr TransformVerifyMethods = NULL;
static xmlHashTablePtr TransformGetDataTypeMethods = NULL;
static xmlHashTablePtr TransformPushBinMethods = NULL;
static xmlHashTablePtr TransformPopBinMethods = NULL;
static xmlHashTablePtr TransformPushXmlMethods = NULL;
static xmlHashTablePtr TransformPopXmlMethods = NULL;
static xmlHashTablePtr TransformExecuteMethods = NULL;

static int xmlsec_TransformInitializeMethod(xmlSecTransformPtr transform) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformInitializeMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "O", wrap_xmlSecTransformPtr(transform));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static void xmlsec_TransformFinalizeMethod(xmlSecTransformPtr transform) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformFinalizeMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "O", wrap_xmlSecTransformPtr(transform));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static xmlSecTransformDataType xmlsec_TransformGetDataTypeMethod(xmlSecTransformPtr transform,
								 xmlSecTransformMode mode,
								 xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformGetDataTypeMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OiO", wrap_xmlSecTransformPtr(transform),
		       mode, wrap_xmlSecTransformCtxPtr(transformCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformNodeReadMethod(xmlSecTransformPtr transform,
					  xmlNodePtr node,
					  xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformNodeReadMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OOO", wrap_xmlSecTransformPtr(transform),
		       wrap_xmlNodePtr(node),
		       wrap_xmlSecTransformCtxPtr(transformCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformNodeWriteMethod(xmlSecTransformPtr transform,
					   xmlNodePtr node,
					   xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformNodeWriteMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OOO", wrap_xmlSecTransformPtr(transform),
		       wrap_xmlNodePtr(node),
		       wrap_xmlSecTransformCtxPtr(transformCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformSetKeyRequirementsMethod(xmlSecTransformPtr transform,
						    xmlSecKeyReqPtr keyReq) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformSetKeyRequirementsMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OO", wrap_xmlSecTransformPtr(transform),
		       wrap_xmlSecKeyReqPtr(keyReq));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformSetKeyMethod(xmlSecTransformPtr transform,
					xmlSecKeyPtr key) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformSetKeyMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OO", wrap_xmlSecTransformPtr(transform),
		       wrap_xmlSecKeyPtr(key));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformVerifyMethod(xmlSecTransformPtr transform,
					const xmlSecByte *data,
					xmlSecSize dataSize,
					xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup2(TransformVerifyMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OsiO", wrap_xmlSecTransformPtr(transform),
		       data, dataSize,
		       wrap_xmlSecTransformCtxPtr(transformCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformPushBinMethod(xmlSecTransformPtr transform,
					 const xmlSecByte *data,
					 xmlSecSize dataSize,
					 int final,
					 xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup2(TransformPushBinMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OsiiO", wrap_xmlSecTransformPtr(transform),
		       data, dataSize, final,
		       wrap_xmlSecTransformCtxPtr(transformCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformPopBinMethod(xmlSecTransformPtr transform,
					xmlSecByte *data,
					xmlSecSize maxDataSize,
					xmlSecSize *dataSize,
					xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup2(TransformPopBinMethods, transform->id->name,
			transform->id->href);

  // FIXME -> dataSize
  args = Py_BuildValue((char *) "OsiOO", wrap_xmlSecTransformPtr(transform),
		       data, maxDataSize, PyCObject_FromVoidPtr(dataSize, NULL),
		       wrap_xmlSecTransformCtxPtr(transformCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformPushXmlMethod(xmlSecTransformPtr transform,
					 xmlSecNodeSetPtr nodes,
					 xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup2(TransformPushXmlMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OOO", wrap_xmlSecTransformPtr(transform),
		       wrap_xmlSecNodeSetPtr(nodes),
		       wrap_xmlSecTransformCtxPtr(transformCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformPopXmlMethod(xmlSecTransformPtr transform,
					xmlSecNodeSetPtr *nodes,
					xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup2(TransformPopXmlMethods, transform->id->name,
			transform->id->href);

  // FIXME -> nodes
  args = Py_BuildValue((char *) "OOO", wrap_xmlSecTransformPtr(transform),
		       PyCObject_FromVoidPtr(nodes, NULL),
		       wrap_xmlSecTransformCtxPtr(transformCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_TransformExecuteMethod(xmlSecTransformPtr transform,
					 int last,
					 xmlSecTransformCtxPtr transformCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup2(TransformExecuteMethods, transform->id->name,
			transform->id->href);

  args = Py_BuildValue((char *) "OiO", wrap_xmlSecTransformPtr(transform),
		       last,
		       wrap_xmlSecTransformCtxPtr(transformCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

/******************************************************************************/

PyObject *transforms_TransformIdCreate(PyObject *self, PyObject *args) {
  PyObject *initialize_obj, *finalize_obj, *readNode_obj, *writeNode_obj;
  PyObject *setKeyReq_obj, *setKey_obj, *verify_obj, *getDataType_obj;
  PyObject *pushBin_obj, *popBin_obj, *pushXml_obj, *popXml_obj, *execute_obj;
  xmlSecSize klassSize;
  xmlSecSize objSize;
  const xmlChar *name;
  const xmlChar *href;
  xmlSecTransformUsage usage;
  struct _xmlSecTransformKlass *transformId;

  if (CheckArgs(args, "IISSIccccccccccccc:keyTransformIdCreate")) {
    if (!PyArg_ParseTuple(args, (char *) "iissiOOOOOOOOOOOOO:keyTransformIdCreate",
			  &klassSize, &objSize, &name, &href, &usage,
			  &initialize_obj, &finalize_obj, &readNode_obj,
			  &writeNode_obj, &setKeyReq_obj, &setKey_obj,
			  &verify_obj, &getDataType_obj, &pushBin_obj,
			  &popBin_obj, &pushXml_obj, &popXml_obj,
			  &execute_obj))
    return NULL;
  }
  else return NULL;

  if (TransformInitializeMethods == NULL && initialize_obj != Py_None)
    TransformInitializeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformFinalizeMethods == NULL && finalize_obj != Py_None)
    TransformFinalizeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformNodeReadMethods == NULL && readNode_obj != Py_None)
    TransformNodeReadMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformNodeWriteMethods == NULL && writeNode_obj != Py_None)
    TransformNodeWriteMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformSetKeyRequirementsMethods == NULL && setKeyReq_obj != Py_None)
    TransformSetKeyRequirementsMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformSetKeyMethods == NULL && setKey_obj != Py_None)
    TransformSetKeyMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformVerifyMethods == NULL && verify_obj != Py_None)
    TransformVerifyMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformGetDataTypeMethods == NULL && getDataType_obj != Py_None)
    TransformGetDataTypeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformPushBinMethods == NULL && pushBin_obj != Py_None)
    TransformPushBinMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformPopBinMethods == NULL && popBin_obj != Py_None)
    TransformPopBinMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformPushXmlMethods == NULL && pushXml_obj != Py_None)
    TransformPushXmlMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformPopXmlMethods == NULL && popXml_obj != Py_None)
    TransformPopXmlMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (TransformExecuteMethods == NULL && execute_obj != Py_None)
    TransformExecuteMethods = xmlHashCreate(HASH_TABLE_SIZE);

  if (initialize_obj != Py_None)
    xmlHashAddEntry2(TransformInitializeMethods, name, href, initialize_obj);
  if (finalize_obj != Py_None)
    xmlHashAddEntry2(TransformFinalizeMethods, name, href, finalize_obj);
  if (readNode_obj != Py_None)
    xmlHashAddEntry2(TransformNodeReadMethods, name, href, readNode_obj);
  if (writeNode_obj != Py_None)
    xmlHashAddEntry2(TransformNodeWriteMethods, name, href, writeNode_obj);
  if (setKeyReq_obj != Py_None)
    xmlHashAddEntry2(TransformSetKeyRequirementsMethods, name, href, setKeyReq_obj);
  if (setKey_obj != Py_None)
    xmlHashAddEntry2(TransformSetKeyMethods, name, href, setKey_obj);
  if (verify_obj != Py_None)
    xmlHashAddEntry2(TransformVerifyMethods, name, href, verify_obj);
  if (getDataType_obj != Py_None)
    xmlHashAddEntry2(TransformGetDataTypeMethods, name, href, getDataType_obj);
  if (pushBin_obj != Py_None)
    xmlHashAddEntry2(TransformPushBinMethods, name, href, pushBin_obj);
  if (popBin_obj != Py_None)
    xmlHashAddEntry2(TransformPopBinMethods, name, href, popBin_obj);
  if (pushXml_obj != Py_None)
    xmlHashAddEntry2(TransformPushXmlMethods, name, href, pushXml_obj);
  if (popXml_obj != Py_None)
    xmlHashAddEntry2(TransformPopXmlMethods, name, href, popXml_obj);
  if (execute_obj != Py_None)
    xmlHashAddEntry2(TransformExecuteMethods, name, href, execute_obj);

  transformId = xmlMalloc(sizeof(xmlSecTransformKlass));

  /* FIXME
    transformId->klassSize = klassSize;
    transformId->objSize = objSize;
  */
  transformId->klassSize = sizeof(xmlSecTransformKlass);
  transformId->objSize = sizeof(xmlSecTransform);

  transformId->name = name;
  transformId->href = href;
  transformId->usage = usage;
  if (initialize_obj != Py_None)
    transformId->initialize = xmlsec_TransformInitializeMethod;
  else
    transformId->initialize = NULL;
  if (finalize_obj != Py_None)
    transformId->finalize = xmlsec_TransformFinalizeMethod;
  else
    transformId->finalize = NULL;
  if (readNode_obj != Py_None)
    transformId->readNode = xmlsec_TransformNodeReadMethod;
  else
    transformId->readNode = NULL;
  if (writeNode_obj != Py_None)
    transformId->writeNode = xmlsec_TransformNodeWriteMethod;
  else
    transformId->writeNode = NULL;
  if (setKeyReq_obj != Py_None)
    transformId->setKeyReq = xmlsec_TransformSetKeyRequirementsMethod;
  else
    transformId->setKeyReq = NULL;
  if (setKey_obj != Py_None)
    transformId->setKey = xmlsec_TransformSetKeyMethod;
  else
    transformId->setKey = NULL;
  if (verify_obj != Py_None)
    transformId->verify = xmlsec_TransformVerifyMethod;
  else
    transformId->verify = NULL;
  if (getDataType_obj != Py_None)
    transformId->getDataType = xmlsec_TransformGetDataTypeMethod;
  else
    transformId->getDataType = NULL;
  if (pushBin_obj != Py_None)
    transformId->pushBin = xmlsec_TransformPushBinMethod;
  else
    transformId->pushBin = NULL;
  if (popBin_obj != Py_None)
    transformId->popBin = xmlsec_TransformPopBinMethod;
  else
    transformId->popBin = NULL;
  if (pushXml_obj != Py_None)
    transformId->pushXml = xmlsec_TransformPushXmlMethod;
  else
    transformId->pushXml = NULL;
  if (popXml_obj != Py_None)
    transformId->popXml = xmlsec_TransformPopXmlMethod;
  else
    transformId->popXml = NULL;
  if (execute_obj != Py_None)
    transformId->execute = xmlsec_TransformExecuteMethod;
  else
    transformId->execute = NULL;

  Py_XINCREF(initialize_obj);
  Py_XINCREF(finalize_obj);
  Py_XINCREF(readNode_obj);
  Py_XINCREF(writeNode_obj);
  Py_XINCREF(setKeyReq_obj);
  Py_XINCREF(setKey_obj);
  Py_XINCREF(verify_obj);
  Py_XINCREF(getDataType_obj);
  Py_XINCREF(pushBin_obj);
  Py_XINCREF(popBin_obj);
  Py_XINCREF(pushXml_obj);
  Py_XINCREF(popXml_obj);
  Py_XINCREF(execute_obj);

  return (wrap_xmlSecTransformId(transformId));
}
