typedef struct {
    PyObject_HEAD
    xmlSecDSigCtxPtr obj;
} xmlSecDSigCtxPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecDSigReferenceCtxPtr obj;
} xmlSecDSigReferenceCtxPtr_object;

#define xmlSecDSigCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecDSigCtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecDSigReferenceCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecDSigReferenceCtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecDSigCtxPtr(xmlSecDSigCtxPtr ctx);
PyObject *wrap_xmlSecDSigReferenceCtxPtr(xmlSecDSigReferenceCtxPtr ctx);

PyObject *xmlSecDSigCtx_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecDSigCtx_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_DSigCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxVerify(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxEnableReferenceTransform(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxEnableSignatureTransform(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxGetPreSignBuffer(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxDebugXmlDump(PyObject *self, PyObject *args);

PyObject *xmlSecDSigReferenceCtx_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecDSigReferenceCtx_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_DSigReferenceCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxProcessNode(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxGetPreDigestBuffer(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxDebugXmlDump(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigReferenceCtxListId(PyObject *self, PyObject *args);
