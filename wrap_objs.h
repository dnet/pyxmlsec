#ifndef __PYXMLSEC_WRAP_OBJS_H__
#define __PYXMLSEC_WRAP_OBJS_H__

#undef _POSIX_C_SOURCE
#include <Python.h>

#include <libxml/xpath.h>
#include <libxml/xmlmemory.h>

#include <xmlsec/xmlsec.h>

typedef struct {
    PyObject_HEAD
    xmlDocPtr obj;
} xmlDocPtr_object;

typedef struct {
    PyObject_HEAD
    xmlNodePtr obj;
} xmlNodePtr_object;

typedef struct {
    PyObject_HEAD
    xmlOutputBufferPtr obj;
} xmlOutputBufferPtr_object;

typedef struct {
    PyObject_HEAD
    xmlNodeSetPtr obj;
} xmlNodeSetPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecPtr obj;
} xmlSecPtr_object;

/* Functions to wrap LibXML Python objects -> LibXML C objects */
#define xmlDocPtr_get(v) (((v) == Py_None) ? NULL : (((xmlDocPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlNodePtr_get(v) (((v) == Py_None) ? NULL : (((xmlNodePtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlNodeSetPtr_get(v) (((v) == Py_None) ? NULL : (((xmlNodeSetPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlOutputBufferPtr_get(v) (((v) == Py_None) ? NULL : (((xmlOutputBufferPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

/* Functions to wrap XMLSec Python objects -> XMLSec C objects */
#define xmlSecPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

/* Functions to wrap Python objects -> C objects */
#define PythonFile_get(v) (((v) == Py_None) ? NULL : (PyFile_Check(v) ? (PyFile_AsFile(v)) : stdout))
xmlChar **PythonStringList_get(PyObject *list_obj);

PyObject *wrap_int(int val);
PyObject *wrap_charPtr(char *str);
PyObject *wrap_charPtrConst(const char *str);

PyObject *wrap_xmlCharPtr(xmlChar *str);
PyObject *wrap_xmlCharPtrConst(const xmlChar *str);
PyObject *wrap_xmlDocPtr(xmlDocPtr doc);
PyObject *wrap_xmlNodePtr(xmlNodePtr node);
PyObject *wrap_xmlNodeSetPtr(xmlNodeSetPtr nset);
PyObject *wrap_xmlOutputBufferPtr(xmlOutputBufferPtr buf);

PyObject *wrap_xmlSecPtr(xmlSecPtr ptr);
PyObject *wrap_xmlSecBytePtr(xmlSecByte *str);
PyObject *wrap_xmlSecBytePtrConst(const xmlSecByte *str);

#endif /* __PYXMLSEC_WRAP_OBJS_H__ */
