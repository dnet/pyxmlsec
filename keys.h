typedef struct {
  PyObject_HEAD
  xmlSecKeyReqPtr obj;
} xmlSecKeyReqPtr_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyPtr obj;
} xmlSecKeyPtr_object;

#define xmlSecKeyReqPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyReqPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeyReqPtr(xmlSecKeyReqPtr key);
PyObject *wrap_xmlSecKeyPtr(xmlSecKeyPtr key);

PyObject *xmlSecKeyReq_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecKeyReq_setattr(PyObject *self, PyObject *args);

PyObject *keys_KeyReqCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqReset(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqCopy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqMatchKey(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqMatchKeyValue(PyObject *self, PyObject *args);

PyObject *xmlSecKey_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecKey_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyEmpty(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDuplicate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyCopy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetType(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetValue(PyObject *self, PyObject *args);
PyObject *xmlsec_KeySetValue(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetData(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyEnsureData(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyAdoptData(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDebugXmlDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGenerate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGenerateByName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyMatch(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadBuffer(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadBinaryFile(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReadMemory(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyIsValid(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyCheckId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyPtrListId(PyObject *self, PyObject *args);
