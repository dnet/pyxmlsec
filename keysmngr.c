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
