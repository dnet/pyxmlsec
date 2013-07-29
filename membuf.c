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
