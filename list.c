/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org/
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

#include "wrap_objs.c"

#include "list.h"

PyObject *xmlsec_PtrListCreate(PyObject *self, PyObject *args) {
  PyObject *id_meth;
  xmlSecPtrListPtr list;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "O:ptrListCreate", &id_meth))
    return NULL;

  list = xmlSecPtrListCreate(PyCObject_AsVoidPtr(id_meth));
  if (list == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) list, (char *) "xmlSecPtrListPtr", NULL);
  return (ret);
}

PyObject *xmlsec_PtrListDestroy(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListDestroy", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  xmlSecPtrListDestroy(list);

  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_PtrListAdd(PyObject *self, PyObject *args) {
  PyObject *list_obj, *item_meth;
  xmlSecPtrListPtr list;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:ptrListAdd", &list_obj, &item_meth))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  ret = xmlSecPtrListAdd(list, BAD_CAST PyCObject_AsVoidPtr(item_meth));
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_PtrListGetSize(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;
  int ret;

  if (!PyArg_ParseTuple(args, "O:ptrListGetSize", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  ret = xmlSecPtrListGetSize(list);
  return Py_BuildValue("i", ret);
}
