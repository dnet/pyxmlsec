typedef struct {
    PyObject_HEAD
    xmlSecBufferPtr obj;
} xmlSecBufferPtr_object;

#define xmlSecBufferPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecBufferPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecBufferPtr(xmlSecBufferPtr buf);

PyObject *xmlSecBuffer_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecBuffer_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_BufferSetDefaultAllocMode(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferGetData(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferSetData(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferGetSize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferSetSize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferGetMaxSize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferSetMaxSize(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferEmpty(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferAppend(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferPrepend(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferRemoveHead(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferRemoveTail(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferReadFile(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferBase64NodeContentRead(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferBase64NodeContentWrite(PyObject *self, PyObject *args);
PyObject *xmlsec_BufferCreateOutputBuffer(PyObject *self, PyObject *args);
