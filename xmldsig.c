/* pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Valery Febvre <vfebvre@easter-eggs.com>
 * http://
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
  PyObject *keyMngr_obj;
  xmlSecDSigCtxPtr dsigCtx;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "O:DSigCtxCreate", &keyMngr_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigCtx, (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_DSigCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;

  if (!PyArg_ParseTuple(args, "O", &dsigCtx_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  xmlSecDSigCtxDestroy(dsigCtx);
  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  PyObject *tmpl_obj;
  xmlSecDSigCtxPtr dsigCtx;
  xmlNodePtr tmpl;
  int ret;

  if (!PyArg_ParseTuple(args, "OO", &dsigCtx_obj, &tmpl_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  tmpl = PyxmlNode_Get(PyObject_GetAttr(tmpl_obj, PyString_FromString("_o")));

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

  if (!PyArg_ParseTuple(args, "OO", &dsigCtx_obj, &node_obj))
    return NULL;

  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  node = PyxmlNode_Get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  ret = xmlSecDSigCtxVerify(dsigCtx, node);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmldsig_set_signKey(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj, *signKey_obj;
  xmlSecDSigCtxPtr dsigCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OO", &dsigCtx_obj, &signKey_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  dsigCtx->signKey = xmlSecKeyPtr_get(PyObject_GetAttr(signKey_obj, PyString_FromString("_o")));

  ret = PyCObject_FromVoidPtrAndDesc((void *) dsigCtx, (char *) "xmlSecDSigCtxPtr", NULL);
  return (ret);
}

PyObject *xmldsig_get_status(PyObject *self, PyObject *args) {
  PyObject *dsigCtx_obj;
  xmlSecDSigCtxPtr dsigCtx;
  int ret;

  if (!PyArg_ParseTuple(args, "O", &dsigCtx_obj))
    return NULL;
  dsigCtx = xmlSecDSigCtxPtr_get(PyObject_GetAttr(dsigCtx_obj, PyString_FromString("_o")));
  ret = dsigCtx->status;

  return Py_BuildValue("i", ret);
}
