/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2013 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This is free software; see COPYING file in the source
 * distribution for preciese wording.
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
