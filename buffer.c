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

PyObject *xmlsec_BufferGetData(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecByte *data;

  if (!PyArg_ParseTuple(args, "O:bufferGetData", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  data = xmlSecBufferGetData(buf);

  return Py_BuildValue("s", data);
}

PyObject *xmlsec_BufferSetData(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;
  int ret;

    if (!PyArg_ParseTuple(args, "Osi:bufferSetData", &buf_obj, &data, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferSetData(buf, data, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferGetSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (!PyArg_ParseTuple(args, "O:bufferGetSize", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  size = xmlSecBufferGetSize(buf);

  return Py_BuildValue("i", size);
}

PyObject *xmlsec_BufferSetSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:bufferSetSize", &buf_obj, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferSetSize(buf, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferGetMaxSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (!PyArg_ParseTuple(args, "O:bufferGetMaxSize", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  size = xmlSecBufferGetMaxSize(buf);

  return Py_BuildValue("i", size);
}

PyObject *xmlsec_BufferSetMaxSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:bufferSetMaxSize", &buf_obj, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferSetMaxSize(buf, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferEmpty(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (!PyArg_ParseTuple(args, "O:bufferEmpty", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  xmlSecBufferEmpty(buf);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_BufferAppend(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;
  int ret;

    if (!PyArg_ParseTuple(args, "Osi:bufferAppend", &buf_obj, &data, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferAppend(buf, data, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferPrepend(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;
  int ret;

    if (!PyArg_ParseTuple(args, "Osi:bufferPrepend", &buf_obj, &data, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferPrepend(buf, data, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferRemoveHead(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:bufferRemoveHead", &buf_obj, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferRemoveHead(buf, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferRemoveTail(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;
  int ret;

  if (!PyArg_ParseTuple(args, "Oi:bufferRemoveTail", &buf_obj, &size))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferRemoveTail(buf, size);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferReadFile(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const char *filename;
  int ret;

  if (!PyArg_ParseTuple(args, "Os:bufferReadFile", &buf_obj, &filename))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  ret = xmlSecBufferReadFile(buf, filename);
  
  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferBase64NodeContentRead(PyObject *self, PyObject *args) {
  PyObject *buf_obj, *node_obj;
  xmlSecBufferPtr buf;
  xmlNodePtr node;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:bufferBase64NodeContentRead", &buf_obj, &node_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  ret = xmlSecBufferBase64NodeContentRead(buf, node);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferBase64NodeContentWrite(PyObject *self, PyObject *args) {
  PyObject *buf_obj, *node_obj;
  xmlSecBufferPtr buf;
  xmlNodePtr node;
  int columns;
  int ret;

  if (!PyArg_ParseTuple(args, "OOi:bufferBase64NodeContentWrite", &buf_obj,
			&node_obj, &columns))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  ret = xmlSecBufferBase64NodeContentWrite(buf, node, columns);

  return Py_BuildValue("i", ret);
}

PyObject *xmlsec_BufferCreateOutputBuffer(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlOutputBufferPtr outBuf;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O:bufferCreateOutputBuffer", &buf_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(PyObject_GetAttr(buf_obj, PyString_FromString("_o")));
  outBuf = xmlSecBufferCreateOutputBuffer(buf);

  ret = PyCObject_FromVoidPtrAndDesc((void *) outBuf, (char *) "xmlOutputBufferPtr", NULL);
  return (ret);
}
