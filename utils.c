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
    /* type is variable */
    else if (format[i] == '?') {
      continue;
    }
  }

  return 1;
}
