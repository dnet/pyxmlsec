#include <xmlsec/keysmngr.h>

typedef struct {
    PyObject_HEAD
    xmlSecKeysMngrPtr obj;
} xmlSecKeysMngrPtr_object;

#define xmlSecKeysMngrPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeysMngrPtr_object *)(v))->obj))

PyObject *xmlsec_KeysMngrCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrDestroy(PyObject *self, PyObject *args);
