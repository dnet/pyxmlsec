typedef struct {
  PyObject_HEAD
  xmlSecKeyReq obj;
} xmlSecKeyReq_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyReqPtr obj;
} xmlSecKeyReqPtr_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyPtr obj;
} xmlSecKeyPtr_object;

#define xmlSecKeyPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyReqPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyReqPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *keys_KeyReqCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqReset(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqMatchKey(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGenerate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGenerateByName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyMatch(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadBuffer(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadBinaryFile(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadMemory(PyObject *self, PyObject *args);
