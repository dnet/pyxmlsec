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

#include "membuf.h"
#include "transforms.h"
#include "buffer.h"

PyObject *xmlsec_TransformMemBufId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformMemBufId));
}

PyObject *xmlsec_TransformMemBufGetBuffer(PyObject *self, PyObject *args) {
  PyObject *transform_obj;
  xmlSecTransformPtr transform;
  xmlSecBufferPtr buf;

  if (CheckArgs(args, "O:transformMemBufGetBuffer")) {
    if (!PyArg_ParseTuple(args, "O:transformMemBufGetBuffer", &transform_obj))
      return NULL;
  }
  else return NULL;

  transform = xmlSecTransformPtr_get(transform_obj);
  buf = xmlSecTransformMemBufGetBuffer(transform);

  return (wrap_xmlSecBufferPtr(buf));
}
