typedef struct {
    PyObject_HEAD
    xmlSecKeyInfoCtxPtr obj;
} xmlSecKeyInfoCtxPtr_object;

#define xmlSecKeyInfoCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyInfoCtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeyInfoCtxPtr(xmlSecKeyInfoCtxPtr ctx);

PyObject *xmlsec_KeyInfoCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxReset(PyObject *self, PyObject *args);
PyObject *keyinfo_get_enabledKeyData(PyObject *self, PyObject *args);
