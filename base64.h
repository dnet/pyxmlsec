typedef struct {
    PyObject_HEAD
    xmlSecBase64CtxPtr obj;
} xmlSecBase64CtxPtr_object;

#define xmlSecBase64CtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecBase64CtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecBase64CtxPtr(xmlSecBase64CtxPtr ctx);

PyObject *xmlsec_Base64CtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64CtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64CtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64CtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64CtxUpdate(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64CtxFinal(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64Encode(PyObject *self, PyObject *args);
PyObject *xmlsec_Base64Decode(PyObject *self, PyObject *args);
