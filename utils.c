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

#include <stdarg.h>

#include "utils.h"

int CheckArgs(PyObject *args, char *format) {
  PyObject *obj;
  int i, nb_args;

  nb_args = PyTuple_GET_SIZE(args);

  /* lowercase means that arg is optional */
  /* O : Instance */
  /* C : Callable */
  /* S : String   */
  /* I : Integer  */
  /* F : File     */
  /* L : List     */
  for (i = 0; i < nb_args; i++) {
    obj = PyTuple_GET_ITEM(args, i);
    /* O or o : instance */
    if (format[i] == 'O' || format[i] == 'o') {
      if (!PyInstance_Check(obj)) {
	if (format[i] == 'o' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be an instance.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* C or c : callable */
    else if (format[i] == 'C' || format[i] == 'c') {
      if (!PyCallable_Check(obj)) {
	if (format[i] == 'c' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be callable.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* S or s : string */
    else if (format[i] == 'S' || format[i] == 's') {
      if (!PyString_Check(obj)) {
	if (format[i] == 's' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be a string.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* I or i : integer */
    else if (format[i] == 'I' || format[i] == 'i') {
      if (!PyInt_Check(obj)) {
	if (format[i] == 'i' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be an integer.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* F or f : file */
    else if (format[i] == 'F' || format[i] == 'f') {
      if (!PyFile_Check(obj)) {
	if (format[i] == 'f' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be a file.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* L or l : list */
    else if (format[i] == 'L' || format[i] == 'l') {
      if (!PyList_Check(obj)) {
	if (format[i] == 'l' && obj == Py_None) continue;
	PyErr_Format(xmlsec_error,
		     "%s() argument %d must be a list.",
		     format + nb_args, i+1);
	return 0;
      }
    }
    /* type is variable */
    else if (format[i] == '?') {
      continue;
    }
  }

  return 1;
}
