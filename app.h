// Crypto Init/shutdown
PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoKeysMngrInit(PyObject *self, PyObject *args);

// app
PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrAdoptKey(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrSave(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeysMngrCertLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args);

// symbols
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args);

PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args);
