/* Crypto init/shutdown */
PyObject *xmlsec_CryptoInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoShutdown(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoKeysMngrInit(PyObject *self, PyObject *args);

/* app */
PyObject *xmlsec_CryptoAppInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppShutdown(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrInit(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrAdoptKey(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppDefaultKeysMngrSave(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeysMngrCertLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeyLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppPkcs12Load(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppKeyCertLoad(PyObject *self, PyObject *args);
PyObject *xmlsec_CryptoAppGetDefaultPwdCallback(PyObject *self, PyObject *args);

/* transform */
PyObject *xmlsec_TransformAes128CbcId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformAes192CbcId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformAes256CbcId(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformKWAes128Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformKWAes192Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformKWAes256Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformDes3CbcId(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformKWDes3Id(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformDsaSha1Id(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformHmacMd5Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacRipemd160Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacSha224Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacSha256Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacSha384Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformHmacSha512Id(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformMd5Id(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformRipemd160Id(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformRsaMd5Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaRipemd160Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha224Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha256Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha384Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaSha512Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaPkcs1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformRsaOaepId(PyObject *self, PyObject *args);

PyObject *xmlsec_TransformSha1Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha224Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha256Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha384Id(PyObject *self, PyObject *args);
PyObject *xmlsec_TransformSha512Id(PyObject *self, PyObject *args);

/* keydata */
PyObject *xmlsec_KeyDataAesId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDesId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataDsaId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataHmacId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataRsaId(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataX509Id(PyObject *self, PyObject *args);
PyObject *xmlsec_KeyDataRawX509CertId(PyObject *self, PyObject *args);
PyObject *xmlsec_X509StoreId(PyObject *self, PyObject *args);
