typedef struct {
    PyObject_HEAD
    xmlSecPtrListPtr obj;
} xmlSecPtrListPtr_object;

#define xmlSecPtrListPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecPtrListPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *xmlsec_PtrListCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListAdd(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListGetSize(PyObject *self, PyObject *args);
