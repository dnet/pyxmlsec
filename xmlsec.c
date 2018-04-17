/* $Id$ 
 *
 * PyXMLSec -- Python bindings for XML Security library (XMLSec)
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

#include "xmlsec.h"

PyObject *xmlsec_Init(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecInit()));
}

PyObject *xmlsec_Shutdown(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecShutdown()));
}

PyObject *xmlsec_CheckVersionExact(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCheckVersionExact()));
}

PyObject *xmlsec_CheckVersion(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecCheckVersion()));
}

PyObject *xmlsec_CheckVersionExt(PyObject *self, PyObject *args) {
  int major;
  int minor;
  int subminor;
  xmlSecCheckVersionMode mode;
  
  if (CheckArgs(args, "IIII:checkVersionExt")) {
    if(!PyArg_ParseTuple(args, (char *) "iiii:checkVersionExt",
			 &major, &minor, &subminor, &mode))
      return NULL;
  }
  else return NULL;

  return (wrap_int(xmlSecCheckVersionExt(major, minor, subminor, mode)));
}
