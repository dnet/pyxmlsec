#include <Python.h>
#include <libxml/tree.h>

typedef struct {
    PyObject_HEAD
    xmlNodePtr obj;
} PyxmlNode_Object;

#define PyxmlNode_Get(v) (((v) == Py_None) ? NULL : (((PyxmlNode_Object *)(v))->obj))

PyObject *xmlsec_error;
