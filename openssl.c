/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org/
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software 
 * without restriction, including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "wrap_objs.h"

#include "openssl.h"

PyObject *xmlsec_OpenSSLAppInit(PyObject *self, PyObject *args) {
  char *config;
  int result;
  if (!PyArg_ParseTuple(args, "z:openSSLAppInit", &config))
    return NULL;
  result = xmlSecOpenSSLAppInit(config);
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}

PyObject *xmlsec_OpenSSLInit(PyObject *self, PyObject *args) {
  int result;
  result = xmlSecOpenSSLInit();
  if (result < 0) {
    PyErr_SetFromErrno(xmlsec_error);
  }
  return Py_BuildValue("i", result);
}
