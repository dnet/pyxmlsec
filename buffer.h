#include <xmlsec/buffer.h>

typedef struct {
    PyObject_HEAD
    xmlSecBufferPtr obj;
} xmlSecBufferPtr_object;

#define xmlSecBufferPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecBufferPtr_object *)(v))->obj))

PyObject *xmlsec_BufferCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferFinalize(PyObject *self, PyObject *args);
