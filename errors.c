/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
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

#include "xmlsecmod.h"

#include "errors.h"

/* not wrap */
PyObject *xmlsec_ErrorsInit(PyObject *self, PyObject *args) {
  xmlSecErrorsInit();

  Py_INCREF(Py_None);
  return (Py_None);
}

/* not wrap */
PyObject *xmlsec_ErrorsShutdown(PyObject *self, PyObject *args) {
  xmlSecErrorsShutdown();

  Py_INCREF(Py_None);
  return (Py_None);
}

static PyObject *ErrorsCallback = NULL;

static void xmlsec_ErrorsCallback(const char *file, int line, const char *func,
				  const char *errorObject,
				  const char *errorSubject, int reason,
				  const char *msg) {
  PyObject *args;

  args = Py_BuildValue((char *) "sisssis", file, line, func, errorObject,
		       errorSubject, reason, msg);

  PyEval_CallObject(ErrorsCallback, args);
  Py_DECREF(args);
}

PyObject *xmlsec_ErrorsSetCallback(PyObject *self, PyObject *args) {
  PyObject *callback_obj;

  if (CheckArgs(args, "C:errorsSetCallback")) {
    if (!PyArg_ParseTuple(args, "O:errorsSetCallback", &callback_obj))
      return NULL;
  }
  else return NULL;

  Py_XINCREF(callback_obj);
  Py_XDECREF(ErrorsCallback);
  ErrorsCallback = callback_obj;

  xmlSecErrorsSetCallback(xmlsec_ErrorsCallback);

  Py_INCREF(Py_None);
  return (Py_None);
}
