#include <xmlsec/keyinfo.h>

typedef struct {
    PyObject_HEAD
    xmlSecKeyInfoCtxPtr obj;
} xmlSecKeyInfoCtxPtr_object;

#define xmlSecKeyInfoCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyInfoCtxPtr_object *)(v))->obj))

PyObject *keyinfo_get_enabledKeyData(PyObject *self, PyObject *args);
