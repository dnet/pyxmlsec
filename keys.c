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
#include "keys.h"

/* static PyObject *dealloc(xmlSecKeyPtr_object *self, PyObject *args) { */
/*   PyMem_DEL(self); */
/*   Py_INCREF(Py_None); */
/*   return Py_None; */
/* } */

/* static PyObject *xmlSecKeyPtr_object_getattr(xmlSecKeyPtr_object *self, char *attr) { */
/*   xmlSecKeyPtr key_ptr = self->obj; */

/*   if (!strcmp(attr, "__members__")) */
/*     return Py_BuildValue("[ssssss]", "name", "value", "dataList", */
/* 			 "usage", "notValidBefore", "notValidAfter"); */
/*   return Py_None; */
/* } */

/* static PyTypeObject xmlSecKeyPtr_object_type = { */
/*     PyObject_HEAD_INIT(&PyType_Type) */
/*     0, */
/*     "xmlSecKeyPtr_object", */
/*     sizeof(xmlSecKeyPtr_object), */
/*     0, */
/*     (destructor)dealloc,                      /\*tp_dealloc*\/ */
/*     0,          /\*tp_print*\/ */
/*     (getattrfunc)xmlSecKeyPtr_object_getattr, /\*tp_getattr*\/ */
/*     (setattrfunc)0, /\*tp_setattr*\/ */
/*     0,          /\*tp_compare*\/ */
/*     0,          /\*tp_repr*\/ */
/*     0,          /\*tp_as_number*\/ */
/*     0,          /\*tp_as_sequence*\/ */
/*     0,          /\*tp_as_mapping*\/ */
/*     0,          /\*tp_hash *\/ */
/* }; */

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
