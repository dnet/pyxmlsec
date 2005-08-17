/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
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

#include "xmlsecmod.h"

#include "keysmngr.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysdata.h"
#include "list.h"

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

PyObject *xmlSecKeysMngr_getattr(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;
  const char *attr;

  if (CheckArgs(args, "OS:keysMngrGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:keysMngrGetAttr", &mngr_obj, &attr))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[sss]", "keysStore", "storesList", "getKey");
  if (!strcmp(attr, "keysStore"))
    return (wrap_xmlSecKeyStorePtr(mngr->keysStore));
  if (!strcmp(attr, "storesList"))
    return (wrap_xmlSecPtrListPtr(&(mngr->storesList)));
  if (!strcmp(attr, "getKey"))
    return PyCObject_FromVoidPtr((void *) mngr->getKey, NULL);

  Py_INCREF(Py_None);
  return (Py_None);
}

static xmlHashTablePtr GetKeyCallbacks = NULL;
static xmlSecKeyPtr xmlsec_GetKeyCallback(xmlNodePtr keyInfoNode,
					  xmlSecKeyInfoCtxPtr keyInfoCtx);

PyObject *xmlSecKeysMngr_setattr(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *value_obj;
  xmlSecKeysMngrPtr mngr;
  const char *name;

  if (CheckArgs(args, "OS?:keysMngrSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:keysMngrSetAttr",
			  &mngr_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
    
  if (!strcmp(name, "keysStore"))
    mngr->keysStore = xmlSecKeyStorePtr_get(value_obj);
  else if (!strcmp(name, "storesList"))
    mngr->storesList = *(xmlSecPtrListPtr_get(value_obj));
  else if (!strcmp(name, "getKey")) {
    if (value_obj != Py_None) {
      if (GetKeyCallbacks == NULL)
	GetKeyCallbacks = xmlHashCreate(HASH_TABLE_SIZE);
      xmlHashAddEntry(GetKeyCallbacks,
		      mngr->keysStore->id->name, value_obj);
      Py_XINCREF(value_obj);
      mngr->getKey = xmlsec_GetKeyCallback;
    }
    else
      mngr->getKey = NULL;
  }

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_KeysMngrCreate(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeysMngrPtr(xmlSecKeysMngrCreate()));
}

PyObject *xmlsec_KeysMngrDestroy(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (CheckArgs(args, "O:keysMngrDestroy")) {
    if (!PyArg_ParseTuple(args, "O:keysMngrDestroy", &mngr_obj))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSO:keysMngrFindKey")) {
    if (!PyArg_ParseTuple(args, "OsO:keysMngrFindKey",
			  &mngr_obj, &name, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;
 
  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  key = xmlSecKeysMngrFindKey(mngr, name, keyInfoCtx);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeysMngrAdoptKeysStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *store_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyStorePtr store;

  if (CheckArgs(args, "OO:keysMngrAdoptKeysStore")) {
    if (!PyArg_ParseTuple(args, "OO:keysMngrAdoptKeysStore", &mngr_obj,
			  &store_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  store = xmlSecKeyStorePtr_get(store_obj);

  return (wrap_int(xmlSecKeysMngrAdoptKeysStore(mngr, store)));
}

PyObject *xmlsec_KeysMngrGetKeysStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (CheckArgs(args, "O:keysMngrGetKeysStore")) {
    if (!PyArg_ParseTuple(args, "O:keysMngrGetKeysStore", &mngr_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);

  return (wrap_xmlSecKeyStorePtr(xmlSecKeysMngrGetKeysStore(mngr)));
}

PyObject *xmlsec_KeysMngrAdoptDataStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *store_obj;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyDataStorePtr store;

  if (CheckArgs(args, "OO:keysMngrAdoptDataStore")) {
    if (!PyArg_ParseTuple(args, "OO:keysMngrAdoptDataStore", &mngr_obj,
			  &store_obj))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  store = xmlSecKeyDataStorePtr_get(store_obj);

  return (wrap_int(xmlSecKeysMngrAdoptDataStore(mngr, store)));
}

PyObject *xmlsec_KeysMngrGetDataStore(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *id_meth;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyDataStoreId id;
  xmlSecKeyDataStorePtr store;

  if (CheckArgs(args, "OO:keysMngrGetDataStore")) {
    if (!PyArg_ParseTuple(args, "OO:keysMngrGetDataStore", &mngr_obj,
			  &id_meth))
      return NULL;
  }
  else return NULL;

  mngr = xmlSecKeysMngrPtr_get(mngr_obj);
  id = (xmlSecKeyDataStoreId) PyCObject_AsVoidPtr(id_meth); // FIXME
  store = xmlSecKeysMngrGetDataStore(mngr, id);

  return (wrap_xmlSecKeyDataStorePtr(store));
}

static xmlSecKeyPtr xmlsec_GetKeyCallback(xmlNodePtr keyInfoNode,
					  xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(GetKeyCallbacks,
		       keyInfoCtx->keysMngr->keysStore->id->name);

  args = Py_BuildValue((char *) "OO", wrap_xmlNodePtr(keyInfoNode),
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (xmlSecKeyPtr_get(result));
}

PyObject *xmlsec_KeysMngrGetKey(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *keyInfoCtx_obj;
  xmlNodePtr keyInfoNode;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:keysMngrGetKey")) {
    if (!PyArg_ParseTuple(args, "OO:keysMngrGetKey",
			  &keyInfoNode_obj, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  key = xmlSecKeysMngrGetKey(keyInfoNode, keyInfoCtx);

  return (wrap_xmlSecKeyPtr(key));
}

/*****************************************************************************/

PyObject *xmlsec_KeyStoreCreate(PyObject *self, PyObject *args) {
  PyObject *id_obj;
  xmlSecKeyStoreId id;
  xmlSecKeyStorePtr keyStore;

  if (CheckArgs(args, "O:keyStoreCreate")) {
    if (!PyArg_ParseTuple(args, "O:keyStoreCreate", &id_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecKeyStoreId_get(id_obj);
  keyStore = xmlSecKeyStoreCreate(id);

  return (wrap_xmlSecKeyStorePtr(keyStore));
}

PyObject *xmlsec_KeyStoreDestroy(PyObject *self, PyObject *args) {
  PyObject *store_obj;
  xmlSecKeyStorePtr store;

  if (CheckArgs(args, "O:keyStoreDestroy")) {
    if (!PyArg_ParseTuple(args, "O:keyStoreDestroy", &store_obj))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSO:keyStoreFindKey")) {
    if (!PyArg_ParseTuple(args, "OsO:keyStoreFindKey", &store_obj, &name,
			  &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;
 
  store = xmlSecKeyStorePtr_get(store_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  key = xmlSecKeyStoreFindKey(store, name, keyInfoCtx);

  return (wrap_xmlSecKeyPtr(key));
}

/******************************************************************************/
/* KeyStoreId                                                                 */
/******************************************************************************/

PyObject *xmlsec_SimpleKeysStoreId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyStoreId(xmlSecSimpleKeysStoreId));
}

static xmlHashTablePtr KeyStoreInitializeMethods = NULL;
static xmlHashTablePtr KeyStoreFinalizeMethods   = NULL;
static xmlHashTablePtr KeyStoreFindKeyMethods    = NULL;

static int xmlsec_KeyStoreInitializeMethod(xmlSecKeyStorePtr store) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyStoreInitializeMethods, store->id->name);

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

  func = xmlHashLookup(KeyStoreFinalizeMethods, store->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyStorePtr(store));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static xmlSecKeyPtr xmlsec_KeyStoreFindKeyMethod(xmlSecKeyStorePtr store,
						 xmlChar *name,
						 xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyStoreFindKeyMethods, store->id->name);

  args = Py_BuildValue((char *) "OsO", wrap_xmlSecKeyStorePtr(store), name,
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  if (result == NULL) {
    return (NULL);
  }
  Py_DECREF(func);
  Py_DECREF(args);

  return (xmlSecKeyPtr_get(result));
}

PyObject *keysmngr_KeyStoreIdCreate(PyObject *self, PyObject *args) {
  PyObject *initialize_obj, *finalize_obj, *findKey_obj;
  xmlSecSize klassSize;
  xmlSecSize objSize;
  const xmlChar *name;    
  struct _xmlSecKeyStoreKlass *storeId;

  if (CheckArgs(args, "IISccc:keyStoreIdCreate")) {
    if(!PyArg_ParseTuple(args, (char *) "iisOOO:keyStoreIdCreate", &klassSize,
			 &objSize, &name, &initialize_obj, &finalize_obj,
			 &findKey_obj))
      return NULL;
  }
  else return NULL;
  
  if (KeyStoreInitializeMethods == NULL && initialize_obj != Py_None)
    KeyStoreInitializeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyStoreFinalizeMethods == NULL && finalize_obj != Py_None)
    KeyStoreFinalizeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyStoreFindKeyMethods == NULL && findKey_obj != Py_None)
    KeyStoreFindKeyMethods = xmlHashCreate(HASH_TABLE_SIZE);

  if (initialize_obj != Py_None)
    xmlHashAddEntry(KeyStoreInitializeMethods, name, initialize_obj);
  if (finalize_obj != Py_None)
    xmlHashAddEntry(KeyStoreFinalizeMethods,   name, finalize_obj);
  if (findKey_obj != Py_None)
    xmlHashAddEntry(KeyStoreFindKeyMethods,    name, findKey_obj);

  storeId = xmlMalloc(sizeof(xmlSecKeyStoreKlass));

  /* FIXME
    storeId->klassSize = klassSize;
    storeId->objSize = objSize;
  */
  storeId->klassSize = sizeof(xmlSecKeyStoreKlass);
  storeId->objSize = sizeof(xmlSecKeyStore);

  storeId->name = strdup(name);
  if (initialize_obj != Py_None)
    storeId->initialize = xmlsec_KeyStoreInitializeMethod;
  else
    storeId->initialize = NULL;
  if (finalize_obj != Py_None)
    storeId->finalize = xmlsec_KeyStoreFinalizeMethod;
  else
    storeId->finalize = NULL;
  if (findKey_obj != Py_None)
    storeId->findKey = xmlsec_KeyStoreFindKeyMethod;
  else
    storeId->findKey = NULL;

  Py_XINCREF(initialize_obj);
  Py_XINCREF(finalize_obj);
  Py_XINCREF(findKey_obj);

  return (wrap_xmlSecKeyStoreId(storeId));
}
