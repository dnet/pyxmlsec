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

#include "transforms.h"
#include "keys.h"

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

/*****************************************************************************/

PyObject *xmlsec_TransformUriTypeCheck(PyObject *self, PyObject *args) {
  xmlSecTransformUriType type;
  const xmlChar *uri;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "is:transformUriTypeCheck", &type, &uri))
    return NULL;

  ret = xmlSecTransformUriTypeCheck(type, uri);
  return wrap_int(ret);
}

PyObject *xmlsec_TransformCtxCreate(PyObject *self, PyObject *args) {
  xmlSecTransformCtxPtr ctx;

  ctx = xmlSecTransformCtxCreate();

  return (wrap_xmlSecTransformCtxPtr(ctx));
}

PyObject *xmlsec_TransformCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if(!PyArg_ParseTuple(args, (char *) "O:transformCtxDestroy", &ctx_obj))
    return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxDestroy(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if(!PyArg_ParseTuple(args, (char *) "O:transformCtxInitialize", &ctx_obj))
    return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxInitialize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if(!PyArg_ParseTuple(args, (char *) "O:transformCtxFinalize", &ctx_obj))
    return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxFinalize(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCtxReset(PyObject *self, PyObject *args) {
  PyObject *ctx_obj;
  xmlSecTransformCtxPtr ctx;

  if(!PyArg_ParseTuple(args, (char *) "O:transformCtxReset", &ctx_obj))
    return NULL;

  ctx = xmlSecTransformCtxPtr_get(ctx_obj);
  xmlSecTransformCtxReset(ctx);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_TransformCreate(PyObject *self, PyObject *args) {
  PyObject *id_meth;
  xmlSecTransformPtr transform;

  if(!PyArg_ParseTuple(args, (char *) "O:transformCreate", &id_meth))
    return NULL;

  transform = xmlSecTransformCreate(PyCObject_AsVoidPtr(id_meth));

  return (wrap_xmlSecTransformPtr(transform));
}

PyObject *xmlsec_TransformDestroy(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;

  if(!PyArg_ParseTuple(args, (char *) "O:transformDestroy", &transform_obj))
    return NULL;

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

  if(!PyArg_ParseTuple(args, (char *) "OiO:transformNodeRead", &node_obj,
		       &usage, &transformCtx_obj))
    return NULL;

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

  if(!PyArg_ParseTuple(args, (char *) "OO:transformSetKey", &transform_obj,
		       &key_obj))
    return NULL;

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

  if(!PyArg_ParseTuple(args, (char *) "OO:transformSetKeyReq", &transform_obj,
		       &keyReq_obj))
    return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  ret = xmlSecTransformSetKeyReq(transform, keyReq);

  return (wrap_int(ret));
}

PyObject *xmlsec_TransformBase64Id(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecTransformBase64Id, NULL);
}

PyObject *xmlsec_TransformBase64SetLineSize(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  xmlSecSize lineSize;

  if(!PyArg_ParseTuple(args, (char *) "Oi:transformBase64SetLineSize",
		       &transform_obj, &lineSize))
    return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  xmlSecTransformBase64SetLineSize(transform, lineSize);

  Py_INCREF(Py_None);
  return (Py_None);
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

PyObject *xmlsec_TransformXPointerSetExpr(PyObject *self, PyObject *args) {
  PyObject *transform_obj, *hereNode_obj;
  xmlSecTransformPtr transform;
  const xmlChar *expr;
  xmlSecNodeSetType nodeSetType;
  xmlNodePtr hereNode;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "OsiO:transformXPointerSetExpr",
		       &transform_obj, &expr, &nodeSetType, &hereNode_obj))
    return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  hereNode = xmlNodePtr_get(hereNode_obj);
  ret = xmlSecTransformXPointerSetExpr(transform, expr, nodeSetType, hereNode);

  return (wrap_int(ret));
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

PyObject *xmlsec_TransformVisa3DHackSetID(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  const xmlChar *id;
  int ret;

  if(!PyArg_ParseTuple(args, (char *) "Os:transformVisa3DHackSetID",
		       &transform_obj, &id))
    return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  ret = xmlSecTransformVisa3DHackSetID(transform, id);

  return (wrap_int(ret));
}
