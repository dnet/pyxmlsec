typedef struct {
    PyObject_HEAD
    xmlSecKeysMngrPtr obj;
} xmlSecKeysMngrPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecKeyStorePtr obj;
} xmlSecKeyStorePtr_object;

#define xmlSecKeysMngrPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeysMngrPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyStorePtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyStorePtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeysMngrPtr(xmlSecKeysMngrPtr mngr);
PyObject *wrap_xmlSecKeyStorePtr(xmlSecKeyStorePtr store);

PyObject *xmlsec_KeysMngrCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrFindKey(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrAdoptKeysStore(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrGetKeysStore(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrAdoptDataStore(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrGetDataStore(PyObject *self, PyObject *args);
PyObject *xmlsec_GetKeyCallback(PyObject *self, PyObject *args);
PyObject *xmlsec_KeysMngrGetKey(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyStoreCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyStoreDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyStoreFindKey(PyObject *self, PyObject *args);
PyObject *xmlsec_SimpleKeysStoreId(PyObject *self, PyObject *args);
