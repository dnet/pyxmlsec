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

  return Py_BuildValue("i", 0);
}
