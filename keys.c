/* $Id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Easter-eggs, Valery Febvre
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

#include <Python.h>

#include "xmlsecmod.h"
#include "keys.h"

/*
  KeyReq : the key requirements information.
*/

static PyObject *xmlSecKeyReq_dealloc(xmlSecKeyReq_object *self, PyObject *args) {
  PyMem_DEL(self);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *xmlSecKeyReq_getattr(PyObject *self, char *attr) {
  xmlSecKeyReq key_req = ((xmlSecKeyReq_object *)self)->obj;

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "keyId", "keyType", "keyUsage", "keyBitsSize");

  if (!strcmp(attr, "keyId")) {
    return PyCObject_FromVoidPtrAndDesc((void *) key_req.keyId,
					(char *) "xmlSecKeyDataId", NULL);
  }
  if (!strcmp(attr, "keyType")) {
    return Py_BuildValue("i", key_req.keyType);
  }
  if (!strcmp(attr, "keyUsage")) {
    return Py_BuildValue("i", key_req.keyUsage);
  }
  if (!strcmp(attr, "keyBitsSize")) {
    return Py_BuildValue("i", key_req.keyBitsSize);
  }
  return Py_None;
}

static int xmlSecKeyReq_setattr(PyObject *self, char *attr, PyObject *value) {
  PyObject *new_value;

  if (!strcmp(attr, "keyId")) {
    PyArg_Parse(value, "O", &new_value);
    ((xmlSecKeyReq_object *)self)->obj.keyId = PyCObject_AsVoidPtr(new_value);
    return 0;
  }
  if (!strcmp(attr, "keyType")) {
    PyArg_Parse(value, "i", &(((xmlSecKeyReq_object *)self)->obj.keyType));
    return 0;
  }
  if (!strcmp(attr, "keyUsage")) {
    PyArg_Parse(value, "i", &(((xmlSecKeyReq_object *)self)->obj.keyUsage));
    return 0;
  }
  if (!strcmp(attr, "keyBitsSize")) {
    PyArg_Parse(value, "i", &(((xmlSecKeyReq_object *)self)->obj.keyBitsSize));
    return 0;
  }
  return -1;
}

static PyTypeObject xmlSecKeyReq_type = {
  PyObject_HEAD_INIT(&PyType_Type)
  0,
  "KeyReq",
  sizeof(xmlSecKeyReq_object),
  0,
  (destructor)xmlSecKeyReq_dealloc,  /*tp_dealloc*/
  0,          /*tp_print*/
  (getattrfunc)xmlSecKeyReq_getattr, /*tp_getattr*/
  (setattrfunc)xmlSecKeyReq_setattr, /*tp_setattr*/
  0,          /*tp_compare*/
  0,          /*tp_repr*/
  0,          /*tp_as_number*/
  0,          /*tp_as_sequence*/
  0,          /*tp_as_mapping*/
  0,          /*tp_hash */
};

static PyObject *new_xmlSecKeyReq_object(xmlSecKeyDataId keyId, xmlSecKeyDataType keyType, 
					 xmlSecKeyUsage keyUsage, xmlSecSize keyBitsSize) {
  xmlSecKeyReq_object *keyReq_obj = NULL;
  
  keyReq_obj = PyObject_NEW(xmlSecKeyReq_object, &xmlSecKeyReq_type);
  if (keyReq_obj == NULL) return NULL;
  
  keyReq_obj->obj.keyId       = keyId;
  keyReq_obj->obj.keyType     = keyType;
  keyReq_obj->obj.keyUsage    = keyUsage;
  keyReq_obj->obj.keyBitsSize = keyBitsSize;
  
  return (PyObject *)keyReq_obj;
}

PyObject *keys_KeyReqCreate(PyObject *self, PyObject *args) {
  PyObject *keyId_meth;
  xmlSecKeyDataType keyType;
  xmlSecKeyUsage keyUsage;
  xmlSecSize keyBitsSize;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "Oiii:keyReqCreate", &keyId_meth, &keyType,
			&keyUsage, &keyBitsSize))
    return NULL;

  ret = new_xmlSecKeyReq_object(PyCObject_AsVoidPtr(keyId_meth),
				keyType, keyUsage, keyBitsSize);
  //return PyCObject_FromVoidPtrAndDesc((void *) ret,
  //				      (char *) "xmlSecKeyReq_object", NULL);;
  return ret;
}

PyObject *xmlsec_KeyReqInitialize(PyObject *self, PyObject *args) {
  xmlSecKeyReq_object *keyReq_obj = NULL;
  xmlSecKeyReq keyReq;
  int ret;

  if (!PyArg_ParseTuple(args, "O:keyReqInitialize", &keyReq_obj))
    return NULL;

  keyReq = keyReq_obj->obj;
  ret = xmlSecKeyReqInitialize(&keyReq);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_KeyReqFinalize(PyObject *self, PyObject *args) {
  xmlSecKeyReq_object *keyReq_obj = NULL;
  xmlSecKeyReq keyReq;

  if (!PyArg_ParseTuple(args, "O:keyReqFinalize", &keyReq_obj))
    return NULL;

  keyReq = keyReq_obj->obj;
  xmlSecKeyReqFinalize(&keyReq);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_KeyReqReset(PyObject *self, PyObject *args) {
  xmlSecKeyReq_object *keyReq_obj = NULL;
  xmlSecKeyReq keyReq;

  if (!PyArg_ParseTuple(args, "O:keyReqReset", &keyReq_obj))
    return NULL;

  keyReq = keyReq_obj->obj;
  xmlSecKeyReqReset(&keyReq);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_KeyReqMatchKey(PyObject *self, PyObject *args) {
  xmlSecKeyReq_object *keyReq_obj = NULL;
  PyObject *key_obj;
  xmlSecKeyReq keyReq;
  xmlSecKeyPtr key;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:keyReqMatchKey", &keyReq_obj, &key_obj))
    return NULL;

  keyReq = keyReq_obj->obj;
  key = (xmlSecKeyPtr)xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  ret = xmlSecKeyReqMatchKey(&keyReq, key);
  
  return Py_BuildValue("i", ret);
}

/*
  Key
*/

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args) {
  xmlSecKeyPtr key;
  PyObject *ret = NULL;

  key = xmlSecKeyCreate();
  ret = PyCObject_FromVoidPtrAndDesc((void *) ret, (char *) "xmlSecKeyPtr", NULL);
  return (ret);
}

PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (!PyArg_ParseTuple(args, "O:keyDestroy", &key_obj))
    return NULL;

  key = (xmlSecKeyPtr)xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  xmlSecKeyDestroy(key);

  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_KeyGetName(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (!PyArg_ParseTuple(args, "O:keyGetName", &key_obj))
    return NULL;
  
  key = (xmlSecKeyPtr)xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  return Py_BuildValue("s", key->name);
}

PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;
  const xmlChar *name;
  int result;
  
  if (!PyArg_ParseTuple(args, "Os:keySetName", &key_obj, &name))
    return NULL;

  key = (xmlSecKeyPtr)xmlSecKeyPtr_get(PyObject_GetAttr(key_obj, PyString_FromString("_o")));
  result = xmlSecKeySetName(key, name);
  return Py_BuildValue("i", result);
}
