#include <xmlsec/transforms.h>

typedef struct {
    PyObject_HEAD
    xmlSecTransformPtr obj;
} xmlSecTransformPtr_object;
#define xmlSecTransformPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecTransformPtr_object *)(v))->obj))

PyObject *xmlsec_TransformInclC14NId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformExclC14NId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformEnvelopedId(PyObject *self, PyObject *args);
