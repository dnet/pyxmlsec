#include <Python.h>
#include <libxml/tree.h>

typedef struct {
    PyObject_HEAD
    xmlNodePtr obj;
} xmlNodePtr_object;

#define xmlNodePtr_get(v) (((v) == Py_None) ? NULL : (((xmlNodePtr_object *)(v))->obj))

PyObject *xmlsec_error;
