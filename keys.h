#include <xmlsec/keys.h>

typedef struct {
  PyObject_HEAD
  xmlSecKeyReq obj;
} xmlSecKeyReq_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyPtr obj;
} xmlSecKeyPtr_object;

#define xmlSecKeyPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyPtr_object *)(v))->obj))

PyObject *keys_KeyReqCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqReset(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyReqMatchKey(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyGetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args);
