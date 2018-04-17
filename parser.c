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

#include "xmlsecmod.h"

#include "parser.h"
#include "transforms.h"

PyObject *xmlsec_ParseFile(PyObject *self, PyObject *args) {
  const char *filename;
  xmlDocPtr doc;

  if (CheckArgs(args, "S:parseFile")) {
    if (!PyArg_ParseTuple(args, "s:parseFile", &filename))
      return NULL;
  }
  else return NULL;

  doc = xmlSecParseFile(filename);
  
  return (wrap_xmlDocPtr(doc));
}

PyObject *xmlsec_ParseMemory(PyObject *self, PyObject *args) {
  const xmlSecByte *buffer;
  xmlSecSize size;
  int recovery;
  xmlDocPtr doc;

  if (CheckArgs(args, "SII:parseMemory")) {
    if (!PyArg_ParseTuple(args, "sii:parseMemory", &buffer, &size, &recovery))
      return NULL;
  }
  else return NULL;

  doc = xmlSecParseMemory(buffer, size, recovery);
  
  return (wrap_xmlDocPtr(doc));
}

PyObject *xmlsec_ParseMemoryExt(PyObject *self, PyObject *args) {
  const xmlSecByte *prefix;
  xmlSecSize prefixSize;
  const xmlSecByte *buffer;
  xmlSecSize bufferSize;
  const xmlSecByte *postfix;
  xmlSecSize postfixSize;
  xmlDocPtr doc;

  if (CheckArgs(args, "SISISI:parseMemoryExt")) {
    if (!PyArg_ParseTuple(args, "sisisi:parseMemoryExt", &prefix, &prefixSize,
			  &buffer, &bufferSize, &postfix, &postfixSize))
      return NULL;
  }
  else return NULL;
  
  doc = xmlSecParseMemoryExt(prefix, prefixSize,
			     buffer, bufferSize,
			     postfix, postfixSize);
  
  return (wrap_xmlDocPtr(doc));
}

PyObject *xmlsec_TransformXmlParserId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecTransformId(xmlSecTransformXmlParserId));
}
