/* $Id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
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
#include "keysmngr.h"
#include "keyinfo.h"

PyObject *xmlsec_KeyInfoCtxCreate(PyObject *self, PyObject *args) {
  PyObject *mngr_obj;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxCreate", &mngr_obj))
    return NULL;

  if (mngr_obj != Py_None)
    mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  /* mngr may be NULL */
  keyInfoCtx = xmlSecKeyInfoCtxCreate(mngr);

  ret = PyCObject_FromVoidPtrAndDesc((void *) keyInfoCtx, (char *) "xmlSecKeyInfoCtxPtr", NULL);
  return (ret);
}

PyObject *xmlsec_KeyInfoCtxDestroy(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxDestroy", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  xmlSecKeyInfoCtxDestroy(keyInfoCtx);

  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_KeyInfoCtxInitialize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj, *mngr_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecKeysMngrPtr mngr = NULL;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:keyInfoCtxInitialize", &keyInfoCtx_obj, &mngr_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  if (mngr_obj != Py_None)
    mngr = xmlSecKeysMngrPtr_get(PyObject_GetAttr(mngr_obj, PyString_FromString("_o")));
  
  /* mngr may be NULL */
  ret = xmlSecKeyInfoCtxInitialize(keyInfoCtx, mngr);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_KeyInfoCtxFinalize(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxFinalize", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  
  xmlSecKeyInfoCtxFinalize(keyInfoCtx);
  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_KeyInfoCtxReset(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxReset", &keyInfoCtx_obj))
    return NULL;

  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  xmlSecKeyInfoCtxReset(keyInfoCtx);

  return Py_BuildValue("i", 0);
}

PyObject *keyinfo_get_enabledKeyData(PyObject *self, PyObject *args) {
  PyObject *keyInfoCtx_obj;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  xmlSecPtrListPtr enabledKeyData;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:keyInfoCtxGetEnabledKeyData", &keyInfoCtx_obj))
    return NULL;
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  enabledKeyData = &(keyInfoCtx->enabledKeyData);

  ret = PyCObject_FromVoidPtrAndDesc((void *) enabledKeyData, (char *) "xmlSecPtrListPtr", NULL);
  return (ret);
}
