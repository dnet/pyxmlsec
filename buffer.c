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
#include "buffer.h"

PyObject *xmlsec_BufferCreate(PyObject *self, PyObject *args) {
  xmlSecSize size;
  xmlSecBufferPtr buf;
  PyObject *ret;
  
  if(!PyArg_ParseTuple(args, (char *) "i:bufferCreate", &size))
    return NULL;

  buf = xmlSecBufferCreate(size);
  if (buf == NULL) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  
  ret = PyCObject_FromVoidPtrAndDesc((void *) buf, (char *) "xmlSecBufferPtr", NULL);
  return (ret);
}

PyObject *xmlsec_BufferDestroy(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (!PyArg_ParseTuple(args, "O:bufferDestroy", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  xmlSecBufferDestroy(buf);

  return Py_BuildValue("i", 0);
}

PyObject *xmlsec_BufferInitialize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecSize size;
  xmlSecBufferPtr buf;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:bufferInitialize", &buf_obj, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  
  ret = xmlSecBufferInitialize(buf, size);
  if (ret < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferFinalize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (!PyArg_ParseTuple(args, "O:bufferFinalize", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  xmlSecBufferFinalize(buf);

  return Py_BuildValue("i", 0);
}
