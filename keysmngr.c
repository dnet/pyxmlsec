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

#include <Python.h>

#include "xmlsecmod.h"
#include "keyinfo.h"
#include "keysmngr.h"

PyObject *xmlsec_KeysMngrCreate(PyObject *self, PyObject *args) {
  xmlSecKeysMngrPtr mngr;
  PyObject *ret = NULL;

  mngr = xmlSecKeysMngrCreate();
  ret = PyCObject_FromVoidPtrAndDesc((void *) mngr, (char *) "xmlSecKeysMngrPtr", NULL);
  return (ret);
}

PyObject *xmlsec_KeysMngrDestroy(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr;

  if (!PyArg_ParseTuple(args, "O:keysMngrDestroy", &mngr_obj))
    return NULL;

  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  xmlSecKeysMngrDestroy(mngr);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_KeysMngrFindKey(PyObject *self, PyObject *args) {
  PyObject *mngr_obj, *keyInfoCtx_obj;
  const xmlChar *name;
  xmlSecKeysMngrPtr mngr;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OsO:keysMngrFindKey", &mngr_obj, &name, &keyInfoCtx_obj))
    return NULL;
 
  mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  key = xmlSecKeysMngrFindKey(mngr, name, keyInfoCtx);

  ret = PyCObject_FromVoidPtrAndDesc((void *) key, (char *) "xmlSecKeyPtr", NULL);
  return (ret);
}

PyObject *xmlsec_KeyStoreCreate(PyObject *self, PyObject *args) {
  PyObject *id_meth;
  xmlSecKeyStorePtr keyStore;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:keyStoreCreate", &id_meth))
    return NULL;

  keyStore = xmlSecKeyStoreCreate((xmlSecKeyStoreId) PyCObject_AsVoidPtr(id_meth));
  ret = PyCObject_FromVoidPtrAndDesc((void *) keyStore, (char *) "xmlSecKeyStorePtr", NULL);
  return (ret);  
}

PyObject *xmlsec_KeyStoreDestroy(PyObject *self, PyObject *args) {
  PyObject *store_obj;
  xmlSecKeyStorePtr store;

  if (!PyArg_ParseTuple(args, "O:keyStoreDestroy", &store_obj))
    return NULL;

  store = xmlSecKeyStorePtr_get(PyObject_GetAttr(store_obj, PyString_FromString("_o")));
  xmlSecKeyStoreDestroy(store);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_KeyStoreFindKey(PyObject *self, PyObject *args) {
  PyObject *store_obj, *keyInfoCtx_obj;
  const xmlChar *name;
  xmlSecKeyStorePtr store;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeyPtr key;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "OsO:keyStoreFindKey", &store_obj, &name, &keyInfoCtx_obj))
    return NULL;
 
  store = xmlSecKeyStorePtr_get(PyObject_GetAttr(store_obj, PyString_FromString("_o")));
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  key = xmlSecKeyStoreFindKey(store, name, keyInfoCtx);

  ret = PyCObject_FromVoidPtrAndDesc((void *) key, (char *) "xmlSecKeyPtr", NULL);
  return (ret);
}

PyObject *xmlsec_SimpleKeysStoreId(PyObject *self, PyObject *args) {
  return PyCObject_FromVoidPtr((void *) xmlSecSimpleKeysStoreId, NULL);
}
