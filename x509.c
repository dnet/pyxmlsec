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
#include "keyinfo.h"

PyObject *xmlsec_X509DataGetNodeContent(PyObject *self, PyObject *args) {
  PyObject *node_obj, *keyInfoCtx_obj;
  xmlNodePtr node;
  int deleteChildren;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  int ret;

  if (!PyArg_ParseTuple(args, "OiO:x509DataGetNodeContent", &node_obj,
			&deleteChildren, &keyInfoCtx_obj))
    return NULL;

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(PyObject_GetAttr(keyInfoCtx_obj, PyString_FromString("_o")));
  ret = xmlSecX509DataGetNodeContent(node, deleteChildren, keyInfoCtx);

  return Py_BuildValue("i", ret);
}
