/* $id:$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003
 * http://
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

#include <Python.h>
#include <xmlsec/templates.h>

#include <xmlsec/transforms.h>
#include <xmlsec/crypto.h>

#include "xmlsecmod.h"

PyObject *xmlsec_TmplSignatureCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *c14nMethodId_meth, *signMethodId_meth;
  xmlDocPtr doc;
  const xmlChar *id;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, "OOOz", &doc_obj, &c14nMethodId_meth,
			&signMethodId_meth, &id))
    return NULL;
  
  if (!PyInstance_Check(doc_obj)) {
    printf("doc isn't an Instance !!!\n");
    return NULL;
  }

  doc = (xmlDocPtr)PyxmlNode_Get(PyObject_GetAttr(doc_obj, PyString_FromString("_o")));
  node = xmlSecTmplSignatureCreate((xmlDocPtr)doc,
				   PyCObject_AsVoidPtr(c14nMethodId_meth),
				   PyCObject_AsVoidPtr(signMethodId_meth), id);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureAddReference(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  PyObject *digestMethodId_meth;
  xmlNodePtr signNode;
  const xmlChar *id;
  const xmlChar *uri;
  const xmlChar *type;
  xmlNodePtr ref;

  if (!PyArg_ParseTuple(args, "OOzzz", &signNode_obj, &digestMethodId_meth,
			&id, &uri, &type))
    return NULL;

  signNode = PyxmlNode_Get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  ref = xmlSecTmplSignatureAddReference(signNode,
					PyCObject_AsVoidPtr(digestMethodId_meth),
					NULL, NULL, NULL);
  return PyCObject_FromVoidPtrAndDesc((void *) ref, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplReferenceAddTransform(PyObject *self, PyObject *args) {
  PyObject *referenceNode_obj;
  PyObject *transformId_meth;
  xmlNodePtr referenceNode;
  xmlNodePtr trans;

  if (!PyArg_ParseTuple(args, "OO", &referenceNode_obj, &transformId_meth))
    return NULL;

  referenceNode = PyxmlNode_Get(PyObject_GetAttr(referenceNode_obj, PyString_FromString("_o")));
  trans = xmlSecTmplReferenceAddTransform(referenceNode,
					  PyCObject_AsVoidPtr(transformId_meth));
  return PyCObject_FromVoidPtrAndDesc((void *) trans, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id;
  xmlNodePtr eki;

  if (!PyArg_ParseTuple(args, "Oz", &signNode_obj, &id))
    return NULL;

  signNode = PyxmlNode_Get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  eki = xmlSecTmplSignatureEnsureKeyInfo(signNode, id);
  return PyCObject_FromVoidPtrAndDesc((void *) eki, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddKeyName(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  const xmlChar *name;
  xmlNodePtr kn;

  if (!PyArg_ParseTuple(args, "Oz", &keyInfoNode_obj, &name))
    return NULL;

  keyInfoNode = PyxmlNode_Get(PyObject_GetAttr(keyInfoNode_obj, PyString_FromString("_o")));
  kn = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, name);
  return PyCObject_FromVoidPtrAndDesc((void *) kn, (char *) "xmlNodePtr", NULL);
}
