/* $Id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003
 * http://
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
#include "xmldsig.h"
#include "keys.h"
#include "keysmngr.h"
#include "list.h"

/* static PyObject *dealloc(xmlSecDSigCtxPtr_object *self, PyObject *args) { */
/*   PyMem_DEL(self); */
/*   Py_INCREF(Py_None); */
/*   return Py_None; */
/* } */

/* static PyObject *xmlSecDSigCtxPtr_getattr(xmlSecDSigCtxPtr_object *self, char *attr) { */
/*   xmlSecDSigCtxPtr dsig_ctx_ptr = self->obj; */

/*   if (!strcmp(attr, "__members__")) */
/*     return Py_BuildValue("[sssssssssssssssssssssssss]", "userData", "flags", "flags2", */
/* 			 "keyInfoReadCtx", "keyInfoWriteCtx", "transformCtx", "enabledReferenceUris", */
/* 			 "enabledReferenceTransforms", "referencePreExecuteCallback", */
/* 			 "defSignMethodId", "defC14NMethodId", "defDigestMethodId", */
/* 			 "signKey", "operation", "result", "status", "signMethod", */
/* 			 "c14nMethod", "preSignMemBufMethod", "signValueNode", "id", */
/* 			 "signedInfoReferences", "manifestReferences", */
/* 			 "reserved0", "reserved1"); */
/*   if (!strcmp(attr, "flags")) { */
/*     printf("flags = %d\n", dsig_ctx_ptr->flags); */
/*     return PyInt_FromLong(dsig_ctx_ptr->flags); */
/*   } */
/*   if (!strcmp(attr, "signKey")) { */
    
/*   } */
/*   return NULL; */
/* } */

/* static PyTypeObject xmlSecDSigCtxPtr_type = { */
/*     PyObject_HEAD_INIT(&PyType_Type) */
/*     0, */
/*     "xmlSecDSigCtxPtr_object", */
/*     sizeof(xmlSecDSigCtxPtr_object), */
/*     0, */
/*     (destructor)dealloc,                 /\*tp_dealloc*\/ */
/*     0,          /\*tp_print*\/ */
/*     (getattrfunc)xmlSecDSigCtxPtr_getattr, /\*tp_getattr*\/ */
/*     0,          /\*tp_setattr*\/ */
/*     0,          /\*tp_compare*\/ */
/*     0,          /\*tp_repr*\/ */
/*     0,          /\*tp_as_number*\/ */
/*     0,          /\*tp_as_sequence*\/ */
/*     0,          /\*tp_as_mapping*\/ */
/*     0,          /\*tp_hash *\/ */
/* }; */

PyObject *xmlsec_DSigCtxCreate(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecDSigCtxPtr dsigCtx;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "O:dsigCtxCreate", &mngr_obj))
    return NULL;

  if (mngr_obj != Py_None)
    mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  /* mngr may be NULL */
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if (dsigCtx == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigCtx, (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_DSigCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "O:dsigCtxDestroy", &dsigCtx_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  xmlSecDSigCtxDestroy(dsigCtx);

  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_DSigCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *mngr_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecKeysMngrPtr mngr = NULL;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxInitialize", &dsigCtx_obj, &mngr_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  
  ret = xmlSecDSigCtxInitialize(dsigCtx, mngr);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "O:dsigCtxFinalize", &dsigCtx_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  
  xmlSecDSigCtxFinalize(dsigCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  PyObject *tmpl_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlNodePtr tmpl;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxSign", &dsigCtx_obj, &tmpl_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  tmpl = xmlNodePtr_get(PyObject_GetAttr(tmpl_obj, PyString_FromString("_o")));
  ret = xmlSecDSigCtxSign(dsigCtx, tmpl);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigCtxVerify(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  PyObject *node_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlNodePtr node;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxVerify", &dsigCtx_obj, &node_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  ret = xmlSecDSigCtxVerify(dsigCtx, node);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigCtxEnableReferenceTransform(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *transformId_meth;
  xmlSecDSigCtxPtr dsigCtx;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxEnableReferenceTransform", &dsigCtx_obj, &transformId_meth))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  ret = xmlSecDSigCtxEnableReferenceTransform(dsigCtx, PyCObject_AsVoidPtr(transformId_meth));
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigCtxEnableSignatureTransform(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *transformId_meth;
  xmlSecDSigCtxPtr dsigCtx;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxEnableSignatureTransform", &dsigCtx_obj, &transformId_meth))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  ret = xmlSecDSigCtxEnableSignatureTransform(dsigCtx, PyCObject_AsVoidPtr(transformId_meth));
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigCtxGetPreSignBuffer(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecBufferPtr buf;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:dsigCtxGetPreSignBuffer", &dsigCtx_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  buf = xmlSecDSigCtxGetPreSignBuffer(dsigCtx);
  if (buf < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) buf, (char *) "xmlSecBufferPtr", NULL);
  return (ret);
}

PyObject *xmlsec_DSigCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "Os:dsigCtxDebugDump", &dsigCtx_obj, &output_path))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecDSigCtxDebugDump(dsigCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "Os:dsigCtxDebugXmlDump", &dsigCtx_obj, &output_path))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecDSigCtxDebugXmlDump(dsigCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigReferenceCtxCreate(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigReferenceOrigin origin;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "Oi:dsigReferenceCtxCreate", &dsigCtx_obj, &origin))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  dsigRefCtx = xmlSecDSigReferenceCtxCreate(dsigCtx, origin);
  if (dsigRefCtx == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
    Py_INCREF(Py_None);
    return Py_None;
  }
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigRefCtx,
				     (char *) "xmlSecDSigReferenceCtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_DSigReferenceCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  
  if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxDestroy", &dsigRefCtx_obj))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  xmlSecDSigReferenceCtxDestroy(dsigRefCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigReferenceCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *dsigCtx_obj;
  xmlSecDSigReferenceOrigin origin;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlSecDSigCtxPtr dsigCtx;
  int ret;
  
  if(!PyArg_ParseTuple(args, (char *) "OOi:dsigReferenceCtxInitialize", &dsigRefCtx_obj, &dsigCtx_obj, &origin))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  ret = xmlSecDSigReferenceCtxInitialize(dsigRefCtx, dsigCtx, origin);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigReferenceCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  
  if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxFinalize", &dsigRefCtx_obj))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  xmlSecDSigReferenceCtxFinalize(dsigRefCtx);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigReferenceCtxProcessNode(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj, *node_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlNodePtr node;
  int ret;
  
  if(!PyArg_ParseTuple(args, (char *) "OO:dsigReferenceCtxProcessNode", &dsigRefCtx_obj, &node_obj))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  ret = xmlSecDSigReferenceCtxProcessNode(dsigRefCtx, node);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_DSigReferenceCtxGetPreDigestBuffer(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;
  xmlSecBufferPtr buf;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "O:dsigReferenceCtxGetPreDigestBuffer", &dsigRefCtx_obj))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  buf = xmlSecDSigReferenceCtxGetPreDigestBuffer(dsigRefCtx);
  if (buf == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
    Py_INCREF(Py_None);
    return Py_None;
  }
  else {
    ret = PyCObject_FromVoidPtrAndDesc((void *) buf, (char *) "xmlSecBufferPtr", NULL);
    return (ret);
  }
}

PyObject *xmlsec_DSigReferenceCtxDebugDump(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;

  if (!PyArg_ParseTuple(args, "OO:dsigReferenceCtxDebugDump", &dsigRefCtx_obj, &output_path))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecDSigReferenceCtxDebugDump(dsigRefCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigReferenceCtxDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *dsigRefCtx_obj;
  const char *output_path;
  FILE *output;
  xmlSecDSigReferenceCtxPtr dsigRefCtx;

  if (!PyArg_ParseTuple(args, "OO:dsigReferenceCtxDebugXmlDump", &dsigRefCtx_obj, &output_path))
    return NULL;

  dsigRefCtx = xmlSecDSigReferenceCtxPtr_get(PyObject_GetAttr(dsigRefCtx_obj, PyString_FromString("_o")));
  output = fopen(output_path, "a+");
  xmlSecDSigReferenceCtxDebugXmlDump(dsigRefCtx, output);
  fclose(output);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_DSigReferenceCtxListId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecDSigReferenceCtxListId, NULL);
}

/* ######################################################################### */

PyObject *xmldsig_set_signKey(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *signKey_obj;
  xmlSecDSigCtxPtr dsigCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OO:dsigCtxSetSignKey", &dsigCtx_obj, &signKey_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  dsigCtx->signKey = xmlSecKeyPtr_get(PyObject_GetAttr(signKey_obj, PyString_FromString("_o")));

  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigCtx, (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *xmldsig_set_enabledReferenceUris(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecTransformUriType enabledReferenceUris;
  xmlSecDSigCtxPtr dsigCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "Oi:dsigCtxSetEnabledReferenceUris", &dsigCtx_obj, &enabledReferenceUris))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  dsigCtx->enabledReferenceUris = enabledReferenceUris;

  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigCtx, (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *xmldsig_get_status(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "O:dsigCtxGetStatus", &dsigCtx_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", dsigCtx->status);
}

PyObject *xmldsig_get_keyInfoReadCtx(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecKeyInfoCtxPtr keyInfoReadCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:dsigCtxGetKeyInfoReadCtx", &dsigCtx_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  keyInfoReadCtx = &(dsigCtx->keyInfoReadCtx);

  ret = PyCObject_FromVoidPtrAndDesc((void *) keyInfoReadCtx, (char *) "xmlSecKeyInfoCtxPtr", NULL);
  return (ret);
}

PyObject *xmldsig_get_signedInfoReferences(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlSecPtrListPtr signedInfoReferences;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:dsigCtxGetSignedInfoReferences", &dsigCtx_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  signedInfoReferences = &(dsigCtx->signedInfoReferences);

  ret = PyCObject_FromVoidPtrAndDesc((void *) signedInfoReferences, (char *) "xmlSecPtrListPtr", NULL);
  return (ret);
}
