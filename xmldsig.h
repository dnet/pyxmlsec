#include <xmlsec/xmldsig.h>

typedef struct {
    PyObject_HEAD
    xmlSecDSigCtxPtr obj;
} xmlSecDSigCtxPtr_object;

#define xmlSecDSigCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecDSigCtxPtr_object *)(v))->obj))

PyObject *xmlsec_DSigCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxSign(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxVerify(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxEnableReferenceTransform(PyObject *self, PyObject *args);
PyObject *xmlsec_DSigCtxEnableSignatureTransform(PyObject *self, PyObject *args);

PyObject *xmldsig_set_signKey(PyObject *self, PyObject *args);
PyObject *xmldsig_set_enabledReferenceUris(PyObject *self, PyObject *args);
PyObject *xmldsig_get_status(PyObject *self, PyObject *args);
PyObject *xmldsig_get_keyInfoReadCtx(PyObject *self, PyObject *args);
PyObject *xmldsig_get_signedInfoReferences(PyObject *self, PyObject *args);
