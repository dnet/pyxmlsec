#include <xmlsec/keys.h>

typedef struct {
    PyObject_HEAD
    xmlSecKeyPtr obj;
} xmlSecKeyPtr_object;

#define xmlSecKeyPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyPtr_object *)(v))->obj))

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args);
