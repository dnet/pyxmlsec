typedef struct {
    PyObject_HEAD
    xmlSecTransformCtxPtr obj;
} xmlSecTransformCtxPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecTransformPtr obj;
} xmlSecTransformPtr_object;

typedef struct {
    PyObject_HEAD
    xmlSecTransformId obj;
} xmlSecTransformId_object;

#define xmlSecTransformPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecTransformPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecTransformCtxPtr_get(v) (((v) == Py_None) ? NULL : (((xmlSecTransformCtxPtr_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))
#define xmlSecTransformId_get(v) (((v) == Py_None) ? NULL : (((xmlSecTransformId_object *)(PyObject_GetAttr(v, PyString_FromString("_o"))))->obj))

PyObject *wrap_xmlSecTransformCtxPtr(xmlSecTransformCtxPtr ctx);
PyObject *wrap_xmlSecTransformPtr(xmlSecTransformPtr ctx);
PyObject *wrap_xmlSecTransformId(xmlSecTransformId transformId);

PyObject *xmlsec_TransformUriTypeCheck(PyObject *self, PyObject *args);

PyObject *xmlSecTransformCtx_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecTransformCtx_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformCtxCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformCtxDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformCtxInitialize(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformCtxFinalize(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformCtxReset(PyObject *self, PyObject *args);

PyObject *xmlSecTransform_getattr(PyObject *self, PyObject *args);
PyObject *xmlSecTransform_setattr(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformCreate(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformDestroy(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformNodeRead(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSetKey(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSetKeyReq(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformBase64SetLineSize(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformXPointerSetExpr(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformBase64Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformInclC14NId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformInclC14NWithCommentsId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformExclC14NId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformExclC14NWithCommentsId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformEnvelopedId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformXPathId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformXPath2Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformXPointerId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformXsltId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRemoveXmlTagsC14NId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformVisa3DHackId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformVisa3DHackSetID(PyObject *self, PyObject *args);

PyObject *transforms_TransformIdCreate(PyObject *self, PyObject *args);
