// crytpo
PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args);

// app
PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args);

// symbols
PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args);
