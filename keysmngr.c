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

#include "keysmngr.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysdata.h"

PyObject *wrap_xmlSecKeysMngrPtr(xmlSecKeysMngrPtr mngr) {
  PyObject *ret;

  if (mngr == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) mngr,
				     (char *) "xmlSecKeysMngrPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecKeyStorePtr(xmlSecKeyStorePtr store) {
  PyObject *ret;

  if (store == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) store,
				     (char *) "xmlSecKeyStorePtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecKeyStoreId(xmlSecKeyStoreId storeId) {
  PyObject *ret;

  if (storeId == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) storeId,
				     (char *) "xmlSecKeyStoreId", NULL);
  return (ret);
}

/*****************************************************************************/

PyObject *xmlsec_KeysMngrCreate(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeysMngrPtr(xmlSecKeysMngrCreate()));
}

PyObject *xmlsec_KeysMngrDestroy(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (!PyArg_ParseTuple(args, "O:keysMngrDestroy", &mngr_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  xmlSecKeysMngrDestroy(mngr);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeysMngrFindKey(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *keyInfoCtx_obj;
  const xmlChar *name;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeyPtr key;

  if (!PyArg_ParseTuple(args, "OsO:keysMngrFindKey",
			&mngr_obj, &name, &keyInfoCtx_obj))
    return NULL;
 
  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  key = xmlSecKeysMngrFindKey(mngr, name, keyInfoCtx);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeysMngrAdoptKeysStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *store_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyStorePtr store;

  if (!PyArg_ParseTuple(args, "OO:keysMngrAdoptKeysStore", &mngr_obj, &store_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  store = xmlSecKeyStorePtr_get(store_obj);

  return (wrap_int(xmlSecKeysMngrAdoptKeysStore(mngr, store)));
}

PyObject *xmlsec_KeysMngrGetKeysStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (!PyArg_ParseTuple(args, "O:keysMngrGetKeysStore", &mngr_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_xmlSecKeyStorePtr(xmlSecKeysMngrGetKeysStore(mngr)));
}

PyObject *xmlsec_KeysMngrAdoptDataStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *store_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyDataStorePtr store;

  if (!PyArg_ParseTuple(args, "OO:keysMngrAdoptDataStore", &mngr_obj, &store_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  store = xmlSecKeyDataStorePtr_get(store_obj);

  return (wrap_int(xmlSecKeysMngrAdoptDataStore(mngr, store)));
}

PyObject *xmlsec_KeysMngrGetDataStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *id_meth;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyDataStoreId id;
  xmlSecKeyDataStorePtr store;

  if (!PyArg_ParseTuple(args, "OO:keysMngrGetDataStore", &mngr_obj, &id_meth))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  id = (xmlSecKeyDataStoreId) PyCObject_AsVoidPtr(id_meth);
  store = xmlSecKeysMngrGetDataStore(mngr, id);

  return (wrap_xmlSecKeyDataStorePtr(store));
}

PyObject *xmlsec_GetKeyCallback(PyObject *self, PyObject *args) {
  /* TODO : Not yet implemented */
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeysMngrGetKey(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *keyInfoCtx_obj;
  xmlNodePtr keyInfoNode;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "OO:keysMngrGetKey",
			&keyInfoNode_obj, &keyInfoCtx_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_xmlSecKeyPtr(xmlSecKeysMngrGetKey(keyInfoNode, keyInfoCtx)));
}

/*****************************************************************************/

PyObject *xmlsec_KeyStoreCreate(PyObject *self, PyObject *args) {
  PyObject *id_meth;
  xmlSecKeyStorePtr keyStore;

  if (!PyArg_ParseTuple(args, "O:keyStoreCreate", &id_meth))
    return NULL;

  keyStore = xmlSecKeyStoreCreate((xmlSecKeyStoreId) PyCObject_AsVoidPtr(id_meth));

  return (wrap_xmlSecKeyStorePtr(keyStore));
}

PyObject *xmlsec_KeyStoreDestroy(PyObject *self, PyObject *args) {
  PyObject *store_obj;
  xmlSecKeyStorePtr store;

  if (!PyArg_ParseTuple(args, "O:keyStoreDestroy", &store_obj))
    return NULL;

  store = xmlSecKeyStorePtr_get(store_obj);
  xmlSecKeyStoreDestroy(store);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyStoreFindKey(PyObject *self, PyObject *args) {
  PyObject *store_obj, *keyInfoCtx_obj;
  const xmlChar *name;
  xmlSecKeyStorePtr store;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeyPtr key;

  if (!PyArg_ParseTuple(args, "OsO:keyStoreFindKey", &store_obj, &name, &keyInfoCtx_obj))
    return NULL;
 
  store = xmlSecKeyStorePtr_get(store_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  key = xmlSecKeyStoreFindKey(store, name, keyInfoCtx);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_SimpleKeysStoreId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecSimpleKeysStoreId, NULL);
}

/*****************************************************************************/

static xmlHashTablePtr KeyStoreIdInitializeMethods = NULL;
static xmlHashTablePtr KeyStoreIdFinalizeMethods   = NULL;
static xmlHashTablePtr KeyStoreIdFindKeyMethods    = NULL;

static int xmlsec_KeyStoreInitializeMethod(xmlSecKeyStorePtr store) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyStoreIdInitializeMethods, store->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyStorePtr(store));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static void xmlsec_KeyStoreFinalizeMethod(xmlSecKeyStorePtr store) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyStoreIdFinalizeMethods, store->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyStorePtr(store));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static xmlSecKeyPtr xmlsec_KeyStoreFindKeyMethod(xmlSecKeyStorePtr store,
					 const xmlChar *name,
					 xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyStoreIdFindKeyMethods, store->id->name);

  args = Py_BuildValue((char *) "OsO", wrap_xmlSecKeyStorePtr(store),
		       wrap_xmlCharPtrConst(name),
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  if (result == NULL)
    return (NULL);
  Py_DECREF(func);
  Py_DECREF(args);

  //return (wrap_xmlSecKeyPtr(result));
  return (xmlSecKeyPtr_get(result));
}

PyObject *xmlsec_KeyStoreIdCreate(PyObject *self, PyObject *args) {
  PyObject *initialize_obj, *finalize_obj, *findKey_obj;
  xmlSecSize klassSize;
  xmlSecSize objSize;
  const xmlChar *name;    
  xmlSecKeyStoreId storeId;

  if(!PyArg_ParseTuple(args, (char *) "iisOOO:ptrListIdCreate", &klassSize,
		       &objSize, &name, &initialize_obj, &finalize_obj,
		       &findKey_obj))
    return NULL;
  
  if (KeyStoreIdInitializeMethods == NULL)
    KeyStoreIdInitializeMethods = xmlHashCreate(10);
  if (KeyStoreIdFinalizeMethods == NULL)
    KeyStoreIdFinalizeMethods = xmlHashCreate(10);
  if (KeyStoreIdFindKeyMethods == NULL)
    KeyStoreIdFindKeyMethods = xmlHashCreate(10);
  xmlHashAddEntry(KeyStoreIdInitializeMethods, name, initialize_obj);
  xmlHashAddEntry(KeyStoreIdFinalizeMethods,   name, finalize_obj);
  xmlHashAddEntry(KeyStoreIdFindKeyMethods,    name, findKey_obj);

  storeId = (xmlSecKeyStoreId) xmlMalloc(sizeof(xmlSecKeyStoreKlass));
  storeId->klassSize = klassSize;
  storeId->objSize = objSize;
  storeId->name = name;
  storeId->initialize = xmlsec_KeyStoreInitializeMethod;
  storeId->finalize   = xmlsec_KeyStoreFinalizeMethod;
  storeId->findKey    = xmlsec_KeyStoreFindKeyMethod;

  Py_XINCREF(initialize_obj);
  Py_XINCREF(finalize_obj);
  Py_XINCREF(findKey_obj);

  return (wrap_xmlSecKeyStoreId(storeId));
}
