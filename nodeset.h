typedef struct {
  PyObject_HEAD
  xmlSecNodeSetPtr obj;
} xmlSecNodeSetPtr_object;

#define xmlSecNodeSetPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecNodeSetPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecNodeSetPtr(xmlSecNodeSetPtr nset);

PyObject *xmlSecNodeSet_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecNodeSet_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_NodeSetCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetDocDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetContains(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetAdd(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetAddList(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetGetChildren(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetWalk(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetDumpTextNodes(PyObject *self, PyObject *args);
PyObject *xmlsec_NodeSetDebugDump(PyObject *self, PyObject *args);
