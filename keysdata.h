typedef struct {
  PyObject_HEAD
  xmlSecKeyDataPtr obj;
} xmlSecKeyDataPtr_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyDataId obj;
} xmlSecKeyDataId_object;

typedef struct {
  PyObject_HEAD
  xmlSecKeyDataStorePtr obj;
} xmlSecKeyDataStorePtr_object;

#define xmlSecKeyDataPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyDataPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyDataId_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyDataId_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecKeyDataStorePtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecKeyDataStorePtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecKeyDataPtr(xmlSecKeyDataPtr data);
PyObject *wrap_xmlSecKeyDataId(xmlSecKeyDataId dataId);
PyObject *wrap_xmlSecKeyDataStorePtr(xmlSecKeyDataStorePtr store);

PyObject *xmlsec_KeyDataIdsGet(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataIdsInit(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataIdsShutdown(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataIdsRegisterDefault(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataIdsRegister(PyObject *self, PyObject *args);

PyObject *xmlSecKeyData_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecKeyData_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyDataCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDuplicate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataGenerate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataGetType(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataGetSize(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataGetIdentifier(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDebugXmlDump(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataXmlRead(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataXmlWrite(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataBinRead(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataBinWrite(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataGetName(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataIsValid(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataCheckId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataCheckUsage(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataCheckSize(PyObject *self, PyObject *args);

PyObject *keysdata_KeyDataIdCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataKlassGetName(PyObject *self, PyObject *args);
