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

#include "xmlsecmod.h"

#include "buffer.h"

PyObject *wrap_xmlSecBufferPtr(xmlSecBufferPtr buf) {
  PyObject *ret;

  if (buf == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) buf,
				     (char *) "xmlSecBufferPtr", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *xmlSecBuffer_getattr(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const char *attr;

  if (!PyArg_ParseTuple(args, "Os:bufferGetAttr", &buf_obj, &attr))
    return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "data", "size", "maxSize", "allocMode");
  if (!strcmp(attr, "data"))
    return (wrap_xmlSecBytePtr(buf->data));
  if (!strcmp(attr, "size"))
    return (wrap_int(buf->size));
  if (!strcmp(attr, "maxSize"))
    return (wrap_int(buf->maxSize));
  if (!strcmp(attr, "allocMode"))
    return (wrap_int(buf->allocMode));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecBuffer_setattr(PyObject *self, PyObject *args) {
  PyObject *buf_obj, *value_obj;
  xmlSecBufferPtr buf;
  const char *name;

  if (!PyArg_ParseTuple(args, "OsO:bufferSetAttr",
			&buf_obj, &name, &value_obj))
    return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
    
  if (!strcmp(name, "data"))
    buf->data = PyString_AsString(value_obj);
  else if (!strcmp(name, "size"))
    buf->size = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "maxSize"))
    buf->maxSize = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "allocMode"))
    buf->allocMode = PyInt_AsLong(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_BufferSetDefaultAllocMode(PyObject *self, PyObject *args) {
  xmlSecAllocMode defAllocMode;
  xmlSecSize defInitialSize;

  if (CheckArgs(args, "II:bufferSetDefaultAllocMode")) {
    if(!PyArg_ParseTuple(args, (char *) "ii:bufferSetDefaultAllocMode",
			 &defAllocMode, &defInitialSize))
      return NULL;
  }
  else return NULL;

  xmlSecBufferSetDefaultAllocMode(defAllocMode, defInitialSize);
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_BufferCreate(PyObject *self, PyObject *args) {
  xmlSecSize size;
  xmlSecBufferPtr buf;
  
  if (CheckArgs(args, "I:bufferCreate")) {
    if(!PyArg_ParseTuple(args, (char *) "i:bufferCreate", &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferCreate(size);

  return (wrap_xmlSecBufferPtr(buf));
}

PyObject *xmlsec_BufferDestroy(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:bufferDestroy")) {
    if (!PyArg_ParseTuple(args, "O:bufferDestroy", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  xmlSecBufferDestroy(buf);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_BufferInitialize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecSize size;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "OI:bufferInitialize")) {
    if (!PyArg_ParseTuple(args, "Oi:bufferInitialize", &buf_obj, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferInitialize(buf, size)));
}

PyObject *xmlsec_BufferFinalize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:bufferFinalize")) {
    if (!PyArg_ParseTuple(args, "O:bufferFinalize", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  xmlSecBufferFinalize(buf);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_BufferGetData(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:bufferGetData")) {
    if (!PyArg_ParseTuple(args, "O:bufferGetData", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);

  return (wrap_xmlSecBytePtrConst(xmlSecBufferGetData(buf)));
}

PyObject *xmlsec_BufferSetData(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;

  if (CheckArgs(args, "OSI:bufferSetData")) {
    if (!PyArg_ParseTuple(args, "Osi:bufferSetData", &buf_obj, &data, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);

  return (wrap_int(xmlSecBufferSetData(buf, data, size)));
}

PyObject *xmlsec_BufferGetSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "O:bufferGetSize")) {
    if (!PyArg_ParseTuple(args, "O:bufferGetSize", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  size = xmlSecBufferGetSize(buf);

  return (wrap_int(size));
}

PyObject *xmlsec_BufferSetSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "OI:bufferSetSize")) {
    if (!PyArg_ParseTuple(args, "Oi:bufferSetSize", &buf_obj, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);

  return (wrap_int(xmlSecBufferSetSize(buf, size)));
}

PyObject *xmlsec_BufferGetMaxSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "O:bufferGetMaxSize")) {
    if (!PyArg_ParseTuple(args, "O:bufferGetMaxSize", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  size = xmlSecBufferGetMaxSize(buf);

  return (wrap_int(size));
}

PyObject *xmlsec_BufferSetMaxSize(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "OI:bufferSetMaxSize")) {
    if (!PyArg_ParseTuple(args, "Oi:bufferSetMaxSize", &buf_obj, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);

  return (wrap_int(xmlSecBufferSetMaxSize(buf, size)));
}

PyObject *xmlsec_BufferEmpty(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:bufferEmpty")) {
    if (!PyArg_ParseTuple(args, "O:bufferEmpty", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  xmlSecBufferEmpty(buf);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_BufferAppend(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;

  if (CheckArgs(args, "OSI:bufferAppend")) {
    if (!PyArg_ParseTuple(args, "Osi:bufferAppend", &buf_obj, &data, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferAppend(buf, data, size)));
}

PyObject *xmlsec_BufferPrepend(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const xmlSecByte *data;
  xmlSecSize size;

  if (CheckArgs(args, "OSI:bufferPrepend")) {
    if (!PyArg_ParseTuple(args, "Osi:bufferPrepend", &buf_obj, &data, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferPrepend(buf, data, size)));
}

PyObject *xmlsec_BufferRemoveHead(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "OI:bufferRemoveHead")) {
    if (!PyArg_ParseTuple(args, "Oi:bufferRemoveHead", &buf_obj, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferRemoveHead(buf, size)));
}

PyObject *xmlsec_BufferRemoveTail(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlSecSize size;

  if (CheckArgs(args, "OI:bufferRemoveTail")) {
    if (!PyArg_ParseTuple(args, "Oi:bufferRemoveTail", &buf_obj, &size))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferRemoveTail(buf, size)));
}

PyObject *xmlsec_BufferReadFile(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  const char *filename;

  if (CheckArgs(args, "OS:bufferReadFile")) {
    if (!PyArg_ParseTuple(args, "Os:bufferReadFile", &buf_obj, &filename))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  
  return (wrap_int(xmlSecBufferReadFile(buf, filename)));
}

PyObject *xmlsec_BufferBase64NodeContentRead(PyObject *self, PyObject *args) {
  PyObject *buf_obj, *node_obj;
  xmlSecBufferPtr buf;
  xmlNodePtr node;

  if (CheckArgs(args, "OO:bufferBase64NodeContentRead")) {
    if (!PyArg_ParseTuple(args, "OO:bufferBase64NodeContentRead",
			  &buf_obj, &node_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecBufferBase64NodeContentRead(buf, node)));
}

PyObject *xmlsec_BufferBase64NodeContentWrite(PyObject *self, PyObject *args) {
  PyObject *buf_obj, *node_obj;
  xmlSecBufferPtr buf;
  xmlNodePtr node;
  int columns;

  if (CheckArgs(args, "OO:bufferBase64NodeContentWrite")) {
    if (!PyArg_ParseTuple(args, "OO:bufferBase64NodeContentWrite", &buf_obj,
			  &node_obj, &columns))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecBufferBase64NodeContentWrite(buf, node, columns)));
}

PyObject *xmlsec_BufferCreateOutputBuffer(PyObject *self, PyObject *args) {
  PyObject *buf_obj;
  xmlSecBufferPtr buf;
  xmlOutputBufferPtr outBuf;

  if (CheckArgs(args, "O:bufferCreateOutputBuffer")) {
    if (!PyArg_ParseTuple(args, "O:bufferCreateOutputBuffer", &buf_obj))
      return NULL;
  }
  else return NULL;

  buf = xmlSecBufferPtr_get(buf_obj);
  outBuf = xmlSecBufferCreateOutputBuffer(buf);

  return (wrap_xmlOutputBufferPtr(outBuf));
}
