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

#include "version.h"

PyObject *xmlsec_xmlsec_version(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION));
}

PyObject *xmlsec_xmlsec_version_major(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MAJOR));
}

PyObject *xmlsec_xmlsec_version_minor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MINOR));
}

PyObject *xmlsec_xmlsec_version_subminor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_SUBMINOR));
}

PyObject *xmlsec_xmlsec_version_info(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION_INFO));
}
