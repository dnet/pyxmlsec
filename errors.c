/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
