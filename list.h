typedef struct {
    PyObject_HEAD
    xmlSecPtrListPtr obj;
} xmlSecPtrListPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecPtrListId obj;
} xmlSecPtrListId_object;

#define xmlSecPtrListPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecPtrListPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecPtrListId_get(v) (((v) == Py_None) ? NULL : (((xmlSecPtrListId_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecPtrListPtr(xmlSecPtrListPtr list);
PyObject *wrap_xmlSecPtrListId(xmlSecPtrListId listId);

PyObject *xmlSecPtrList_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecPtrList_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_PtrListCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListEmpty(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListCopy(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListDuplicate(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListGetSize(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListGetItem(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListAdd(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListSet(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListRemove(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListDebugDump(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListDebugXmlDump(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListGetName(PyObject *self, PyObject *args);
PyObject *xmlsec_PtrListIsValid(PyObject *self, PyObject *args);

PyObject *xmlsec_PtrListIdCreate(PyObject *self, PyObject *args);
