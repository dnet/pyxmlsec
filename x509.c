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

#include "keyinfo.h"
#include "x509.h"

PyObject *xmlsec_X509DataGetNodeContent(PyObject *self, PyObject *args) {
  PyObject *node_obj, *keyInfoCtx_obj;
  xmlNodePtr node;
  xmlSecKeyInfoCtxPtr keyInfoCtx;
  int ret;

  if (CheckArgs(args, "OIO:x509DataGetNodeContent")) {
    if (!PyArg_ParseTuple(args, "OiO:x509DataGetNodeContent", &node_obj,
			  &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);
  ret = xmlSecX509DataGetNodeContent(node, keyInfoCtx);

  return wrap_int(ret);
}
