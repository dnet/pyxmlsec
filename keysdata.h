typedef struct {
  PyObject_HEAD
  xmlSecKeyDataPtr obj;
} xmlSecKeyDataPtr_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyDataStorePtr obj;
} xmlSecKeyDataStorePtr_object;

#define xmlSecKeyDataPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyDataPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyDataStorePtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyDataStorePtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeyDataPtr(xmlSecKeyDataPtr data);
PyObject *wrap_xmlSecKeyDataStorePtr(xmlSecKeyDataStorePtr store);
