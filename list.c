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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "wrap_objs.h"

#include "list.h"

PyObject *wrap_xmlSecPtrListPtr(xmlSecPtrListPtr list) {
  PyObject *ret;

  if (list == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) list,
				     (char *) "xmlSecPtrListPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecPtrListId(xmlSecPtrListId listId) {
  PyObject *ret;

  if (listId == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) listId,
				     (char *) "xmlSecPtrListId", NULL);
  return (ret);
}

/******************************************************************************/
/* PtrList                                                                    */
/******************************************************************************/

PyObject *xmlSecPtrList_getattr(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;
  const char *attr;

  if (!PyArg_ParseTuple(args, "Os:ptrListGetAttr", &list_obj, &attr))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sssss]", "id", "data", "use", "max", "allocMode");
  if (!strcmp(attr, "id"))
    return wrap_xmlSecPtrListId(list->id);
  if (!strcmp(attr, "data"))
    return (wrap_xmlSecPtr(list->data));
  if (!strcmp(attr, "use"))
    return (wrap_int(list->use));
  if (!strcmp(attr, "max"))
    return (wrap_int(list->max));
  if (!strcmp(attr, "allocMode"))
    return (wrap_int(list->allocMode));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecPtrList_setattr(PyObject *self, PyObject *args) {
  PyObject *list_obj, *value_obj;
  xmlSecPtrListPtr list;
  const char *name;

  if (!PyArg_ParseTuple(args, "OsO:ptrListSetAttr",
			&list_obj, &name, &value_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
    
  if (!strcmp(name, "id")) {
    Py_XINCREF(value_obj);
    list->id = xmlSecPtrListId_get(value_obj);
  }
  else if (!strcmp(name, "data"))
    list->data = PyCObject_AsVoidPtr(value_obj); // FIXME
  else if (!strcmp(name, "use"))
    list->use = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "max"))
    list->max = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "allocMode"))
    list->allocMode = PyInt_AsLong(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_PtrListCreate(PyObject *self, PyObject *args) {
  PyObject *id_obj;
  xmlSecPtrListPtr list;
  xmlSecPtrListId id = NULL;
  
  if(!PyArg_ParseTuple(args, (char *) "O:ptrListCreate", &id_obj))
    return NULL;

  if (id_obj != Py_None)
    id = xmlSecPtrListId_get(id_obj);
  list = xmlSecPtrListCreate(id);
  
  return (wrap_xmlSecPtrListPtr(list));
}

PyObject *xmlsec_PtrListDestroy(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListDestroy", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  xmlSecPtrListDestroy(list);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_PtrListInitialize(PyObject *self, PyObject *args) {
  PyObject *list_obj, *id_obj;
  xmlSecPtrListPtr list;
  xmlSecPtrListId id = NULL;

  if(!PyArg_ParseTuple(args, (char *) "OO:ptrListInitialize",
		       &list_obj, &id_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  if (id_obj != Py_None)
    id = xmlSecPtrListId_get(id_obj);

  return (wrap_int(xmlSecPtrListInitialize(list, id)));
}

PyObject *xmlsec_PtrListFinalize(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListFinalize", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  xmlSecPtrListFinalize(list);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_PtrListEmpty(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListEmpty", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  xmlSecPtrListEmpty(list);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_PtrListCopy(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecPtrListPtr dst;
  xmlSecPtrListPtr src;

  if (!PyArg_ParseTuple(args, "OO:ptrListCopy", &dst_obj, &src_obj))
    return NULL;

  dst = xmlSecPtrListPtr_get(dst_obj);
  src = xmlSecPtrListPtr_get(src_obj);

  return (wrap_int(xmlSecPtrListCopy(dst, src)));
}

PyObject *xmlsec_PtrListDuplicate(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListDuplicate", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  return (wrap_xmlSecPtrListPtr(xmlSecPtrListDuplicate(list)));
}

PyObject *xmlsec_PtrListGetSize(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListGetSize", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  return (wrap_int(xmlSecPtrListGetSize(list)));
}

PyObject *xmlsec_PtrListGetItem(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;
  xmlSecSize pos;

  if (!PyArg_ParseTuple(args, "Oi:ptrListGetItem", &list_obj, &pos))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  return (wrap_xmlSecPtr(xmlSecPtrListGetItem(list, pos)));
}

PyObject *xmlsec_PtrListAdd(PyObject *self, PyObject *args) {
  PyObject *list_obj, *item_obj;
  xmlSecPtrListPtr list;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:ptrListAdd", &list_obj, &item_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  ret = xmlSecPtrListAdd(list, xmlSecPtr_get(item_obj));

  return (wrap_int(ret));
}

PyObject *xmlsec_PtrListSet(PyObject *self, PyObject *args) {
  PyObject *list_obj, *item_obj;
  xmlSecPtrListPtr list;
  xmlSecSize pos;
  int ret;

  if (!PyArg_ParseTuple(args, "OOi:ptrListSet", &list_obj, &item_obj, &pos))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  ret = xmlSecPtrListSet(list, xmlSecPtr_get(item_obj), pos);

  return (wrap_int(ret));
}

PyObject *xmlsec_PtrListRemove(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;
  xmlSecSize pos;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:ptrListRemove", &list_obj, &pos))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  ret = xmlSecPtrListRemove(list, pos);

  return (wrap_int(ret));
}

PyObject *xmlsec_PtrListDebugDump(PyObject *self, PyObject *args) {
  PyObject *list_obj, *output_obj;
  FILE *output;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "OO:ptrListDebugDump", &list_obj, &output_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  output = PyFile_get(output_obj);
  xmlSecPtrListDebugDump(list, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_PtrListDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *list_obj, *output_obj;
  FILE *output;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "OO:ptrListDebugXmlDump", &list_obj, &output_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);
  output = PyFile_get(output_obj);
  xmlSecPtrListDebugXmlDump(list, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_PtrListGetName(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListGetName", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  return (wrap_xmlCharPtrConst(xmlSecPtrListGetName(list)));
}

PyObject *xmlsec_PtrListIsValid(PyObject *self, PyObject *args) {
  PyObject *list_obj;
  xmlSecPtrListPtr list;

  if (!PyArg_ParseTuple(args, "O:ptrListIsValid", &list_obj))
    return NULL;

  list = xmlSecPtrListPtr_get(list_obj);

  return (wrap_int(xmlSecPtrListIsValid(list)));
}

/******************************************************************************/
/* PtrListId                                                                  */
/******************************************************************************/

static xmlHashTablePtr PtrDuplicateItemMethods    = NULL;
static xmlHashTablePtr PtrDestroyItemMethods      = NULL;
static xmlHashTablePtr PtrDebugDumpItemMethods    = NULL;
static xmlHashTablePtr PtrDebugXmlDumpItemMethods = NULL;

static xmlSecPtr xmlsec_PtrDuplicateItemMethod(xmlSecPtr ptr) {
  xmlSecPtrListPtr list;
  PyObject *args, *result;
  PyObject *func = NULL;

  list = (xmlSecPtrListPtr) ptr;
  func = xmlHashLookup(PtrDestroyItemMethods, list->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecPtr(ptr));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (wrap_xmlSecPtr(result));
}

static void xmlsec_PtrDestroyItemMethod(xmlSecPtr ptr) {
  xmlSecPtrListPtr list;
  PyObject *args, *result;
  PyObject *func = NULL;

  list = (xmlSecPtrListPtr) ptr;
  func = xmlHashLookup(PtrDestroyItemMethods, list->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecPtr(ptr));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static void xmlsec_PtrDebugDumpItemMethod(xmlSecPtr ptr, FILE *output) {
  xmlSecPtrListPtr list;
  PyObject *args, *result;
  PyObject *func = NULL;

  list = (xmlSecPtrListPtr) ptr;
  func = xmlHashLookup(PtrDebugDumpItemMethods, list->id->name);

  /* FIXME */
  args = Py_BuildValue((char *) "OO", wrap_xmlSecPtr(ptr),
		       PyFile_FromFile(output, NULL, NULL, NULL));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static void xmlsec_PtrDebugXmlDumpItemMethod(xmlSecPtr ptr, FILE *output) {
  xmlSecPtrListPtr list;
  PyObject *args, *result;
  PyObject *func = NULL;

  list = (xmlSecPtrListPtr) ptr;
  func = xmlHashLookup(PtrDebugXmlDumpItemMethods, list->id->name);

  /* FIXME */
  args = Py_BuildValue((char *) "OO", wrap_xmlSecPtr(ptr),
		       PyFile_FromFile(output, NULL, NULL, NULL));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

PyObject *xmlsec_PtrListIdCreate(PyObject *self, PyObject *args) {
  PyObject *duplicateItem_obj, *destroyItem_obj;
  PyObject *debugDumpItem_obj, *debugXmlDumpItem_obj;
  const xmlChar *name;
  struct _xmlSecPtrListKlass *listId;

  if(!PyArg_ParseTuple(args, (char *) "sOOOO:ptrListIdCreate", &name,
		       &duplicateItem_obj, &destroyItem_obj, &debugDumpItem_obj,
		       &debugXmlDumpItem_obj))
    return NULL;
  
  if (PtrDuplicateItemMethods == NULL && duplicateItem_obj != Py_None)
    PtrDuplicateItemMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (PtrDestroyItemMethods == NULL && destroyItem_obj != Py_None)
    PtrDestroyItemMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (PtrDebugDumpItemMethods == NULL && debugDumpItem_obj != Py_None)
    PtrDebugDumpItemMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (PtrDebugXmlDumpItemMethods == NULL && debugXmlDumpItem_obj != Py_None)
    PtrDebugXmlDumpItemMethods = xmlHashCreate(HASH_TABLE_SIZE);

  if (duplicateItem_obj != Py_None)
    xmlHashAddEntry(PtrDuplicateItemMethods, name, duplicateItem_obj);
  if (destroyItem_obj != Py_None)
    xmlHashAddEntry(PtrDestroyItemMethods,   name, destroyItem_obj);
  if (debugDumpItem_obj != Py_None)
    xmlHashAddEntry(PtrDebugDumpItemMethods, name, debugDumpItem_obj);
  if (debugXmlDumpItem_obj != Py_None)
    xmlHashAddEntry(PtrDebugXmlDumpItemMethods, name, debugXmlDumpItem_obj);

  listId = xmlMalloc(sizeof(xmlSecPtrListKlass));
  listId->name = name;
  if (duplicateItem_obj != Py_None)
    listId->duplicateItem = xmlsec_PtrDuplicateItemMethod;
  else
    listId->duplicateItem = NULL;
  if (destroyItem_obj != Py_None)
    listId->destroyItem = xmlsec_PtrDestroyItemMethod;
  else
    listId->destroyItem = NULL;
  if (debugDumpItem_obj != Py_None)
    listId->debugDumpItem = xmlsec_PtrDebugDumpItemMethod;
  else
    listId->debugDumpItem = NULL;
  if (debugXmlDumpItem_obj != Py_None)
    listId->debugXmlDumpItem = xmlsec_PtrDebugXmlDumpItemMethod;
  else
    listId->debugXmlDumpItem = NULL;

  Py_XINCREF(duplicateItem_obj);
  Py_XINCREF(destroyItem_obj);
  Py_XINCREF(debugDumpItem_obj);
  Py_XINCREF(debugXmlDumpItem_obj);

  return (wrap_xmlSecPtrListId(listId));
}
