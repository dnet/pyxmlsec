#include "wrap_objs.h"

PyObject *wrap_int(int val) {
  return (Py_BuildValue("i", val));
}

PyObject *wrap_str(char *str) {
  PyObject *ret;

  if (str == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyString_FromString((char *) str);
  xmlFree(str);
  return (ret);
}

/* functions for libxml objects */

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

/* functions for xmlsec objects */

PyObject *wrap_xmlSecTransformPtr(xmlSecTransformPtr transform) {
  PyObject *ret;

  if (transform == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) transform,
				     (char *) "xmlSecTransformPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecTransformCtxPtr(xmlSecTransformCtxPtr ctx) {
  PyObject *ret;

  if (ctx == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) ctx,
				     (char *) "xmlSecTransformCtxPtr", NULL);
  return (ret);
}
