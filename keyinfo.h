typedef struct {
    PyObject_HEAD
    xmlSecKeyInfoCtxPtr obj;
} xmlSecKeyInfoCtxPtr_object;

#define xmlSecKeyInfoCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyInfoCtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeyInfoCtxPtr(xmlSecKeyInfoCtxPtr ctx);

PyObject *xmlSecKeyInfoCtx_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecKeyInfoCtx_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyInfoNodeRead(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoNodeWrite(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxReset(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxCopyUserPref(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxCreateEncCtx(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyInfoCtxDebugXmlDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataNameId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataValueId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataRetrievalMethodId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataEncryptedKeyId(PyObject *self, PyObject *args);
