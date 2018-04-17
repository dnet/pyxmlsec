/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software 
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "wrap_objs.h"

/*****************************************************************************/
/* Functions to wrap Python objects -> C objects                             */
/*****************************************************************************/

xmlChar **PythonStringList_get(PyObject *list_obj) {
  int i;
  xmlChar **list = NULL;

  if (list_obj == Py_None) return NULL;

  /* convert Python list into a NULL terminated C list */
  list = (xmlChar **) xmlMalloc ((PyList_Size(list_obj)+1)*sizeof (xmlChar *));
  for (i=0; i<PyList_Size(list_obj); i++)
    list[i] = (xmlChar *)PyString_AsString(PyList_GetItem(list_obj, i));
  list[i] = NULL;

  return list;
}

/*****************************************************************************/
/* Functions to wrap C objects -> Python objects                             */
/*****************************************************************************/

PyObject *wrap_int(int val) {
  return (Py_BuildValue("i", val));
}

PyObject *wrap_charPtr(char *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString(str);
  /* deallocation */
  free (str);

  return (ret);
}

PyObject *wrap_charPtrConst(const char *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString(str);
  return (ret);
}

/*****************************************************************************/
/* Functions to wrap LibXML objects -> Python objects                        */
/*****************************************************************************/

PyObject *wrap_xmlCharPtr(xmlChar *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString((char *) str);
  /* deallocation */
  xmlFree(str);
  return (ret);
}

PyObject *wrap_xmlCharPtrConst(const xmlChar *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString((char *) str);
  return (ret);
}

PyObject *wrap_xmlDocPtr(xmlDocPtr doc) {
  PyObject *ret;
  
  if (doc == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) doc, (char *) "xmlDocPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlNodePtr(xmlNodePtr node) {
  PyObject *ret;

  if (node == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
  return (ret);
}

PyObject *wrap_xmlNodeSetPtr(xmlNodeSetPtr nset) {
  PyObject *ret;

  if (nset == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) nset, (char *) "xmlNodeSetPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlOutputBufferPtr(xmlOutputBufferPtr buf) {
  PyObject *ret;

  if (buf == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) buf,
				     (char *) "xmlOutputBufferPtr", NULL);
  return (ret);
}

/*****************************************************************************/
/* Functions to wrap XMLSec objects -> Python objects                        */
/*****************************************************************************/

PyObject *wrap_xmlSecPtr(xmlSecPtr ptr) {
  PyObject *ret;

  if (ptr == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = (PyCObject_FromVoidPtr((void *) ptr, NULL));
  return (ret);
}

PyObject *wrap_xmlSecBytePtr(xmlSecByte *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString((char *) str);
  xmlFree(str);
  return (ret);
}

PyObject *wrap_xmlSecBytePtrConst(const xmlSecByte *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString((char *) str);
  return (ret);
}
