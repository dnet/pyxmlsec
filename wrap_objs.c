#include "wrap_objs.h"

PyObject *wrap_int(int val) {
  return (Py_BuildValue("i", val));
}

PyObject *wrap_charPtr(char *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  /* deallocation */
  free (str);
  ret = PyString_FromString(str);
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

/* Functions for libxml objects */

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

/* Functions for xmlsec objects */

PyObject *wrap_xmlSecBytePtrConst(const xmlSecByte *c) {
  if (c == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  return Py_BuildValue("c", c);
}
