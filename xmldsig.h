#include <xmlsec/xmldsig.h>

typedef struct {
    PyObject_HEAD
    xmlSecDSigCtxPtr obj;
} xmlSecDSigCtxPtr_object;

#define xmlSecDSigCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecDSigCtxPtr_object *)(v))->obj))

PyObject *xmlsec_DSigCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args);
PyObject *xmldsig_set_signKey(PyObject *self, PyObject *args);
