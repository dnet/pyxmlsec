#include <xmlsec/xmlsec.h>

#include "xmlsecmod.h"
#include "xmlsec.h"

PyObject *xmlsec_Init(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecInit();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_Shutdown(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecShutdown();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}
