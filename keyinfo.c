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
#include "keyinfo.h"

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
