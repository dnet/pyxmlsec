/* $Id$ 
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

  if (!PyArg_ParseTuple(args, "OOOz:tmplSignatureCreate", &doc_obj,
			&c14nMethodId_meth, &signMethodId_meth, &id))
    return NULL;
  
  if (!PyInstance_Check(doc_obj)) {
    printf("doc isn't an Instance !!!\n");
    return NULL;
  }

  doc = (xmlDocPtr)xmlNodePtr_get(PyObject_GetAttr(doc_obj, PyString_FromString("_o")));
  node = xmlSecTmplSignatureCreate((xmlDocPtr)doc,
				   PyCObject_AsVoidPtr(c14nMethodId_meth),
				   PyCObject_AsVoidPtr(signMethodId_meth), id);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id;
  xmlNodePtr eki;

  if (!PyArg_ParseTuple(args, "Oz:tmplSignatureEnsureKeyInfo", &signNode_obj, &id))
    return NULL;

  signNode = xmlNodePtr_get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  eki = xmlSecTmplSignatureEnsureKeyInfo(signNode, id);
  return PyCObject_FromVoidPtrAndDesc((void *) eki, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureAddReference(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  PyObject *digestMethodId_meth;
  xmlNodePtr signNode;
  const xmlChar *id;
  const xmlChar *uri;
  const xmlChar *type;
  xmlNodePtr ref;

  if (!PyArg_ParseTuple(args, "OOzzz:tmplSignatureAddReference", &signNode_obj,
			&digestMethodId_meth, &id, &uri, &type))
    return NULL;

  signNode = xmlNodePtr_get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  ref = xmlSecTmplSignatureAddReference(signNode,
					PyCObject_AsVoidPtr(digestMethodId_meth),
					id, uri, type);
  return PyCObject_FromVoidPtrAndDesc((void *) ref, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureAddObject(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id;
  const xmlChar *mimeType;
  const xmlChar *encoding;
  xmlNodePtr obj;

  if (!PyArg_ParseTuple(args, "Ozzz:tmplSignatureAddObject", &signNode_obj,
			&id, &mimeType, &encoding))
    return NULL;

  signNode = xmlNodePtr_get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  obj = xmlSecTmplSignatureAddObject(signNode, id, mimeType, encoding);

  return PyCObject_FromVoidPtrAndDesc((void *) obj, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureGetSignMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, "O:tmplSignatureGetSignMethodNode", &signNode_obj))
    return NULL;

  signNode = xmlNodePtr_get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  node = xmlSecTmplSignatureGetSignMethodNode(signNode);
  
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureGetC14NMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;
  
  if (!PyArg_ParseTuple(args, "O:tmplSignatureGetC14NMethodNode", &signNode_obj))
    return NULL;

  signNode = xmlNodePtr_get(PyObject_GetAttr(signNode_obj, PyString_FromString("_o")));
  node = xmlSecTmplSignatureGetC14NMethodNode(signNode);
  
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);  
}

PyObject *xmlsec_TmplReferenceAddTransform(PyObject *self, PyObject *args) {
  PyObject *referenceNode_obj;
  PyObject *transformId_meth;
  xmlNodePtr referenceNode;
  xmlNodePtr transform;

  if (!PyArg_ParseTuple(args, "OO:tmplReferenceAddTransform",
			&referenceNode_obj, &transformId_meth))
    return NULL;

  referenceNode = xmlNodePtr_get(PyObject_GetAttr(referenceNode_obj, PyString_FromString("_o")));
  transform = xmlSecTmplReferenceAddTransform(referenceNode,
					  PyCObject_AsVoidPtr(transformId_meth));
  return PyCObject_FromVoidPtrAndDesc((void *) transform, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplObjectAddSignProperties(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id;
  const xmlChar *target;
  xmlNodePtr signProperties;

  if (!PyArg_ParseTuple(args, "Ozz:tmplObjectAddSignProperties", &objectNode_obj, &id, &target))
    return NULL;

  objectNode = xmlNodePtr_get(PyObject_GetAttr(objectNode_obj, PyString_FromString("_o")));
  signProperties = xmlSecTmplObjectAddSignProperties(objectNode, id, target);

  return PyCObject_FromVoidPtrAndDesc((void *) signProperties, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplObjectAddManifest(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id;
  xmlNodePtr manifest;

  if (!PyArg_ParseTuple(args, "Oz:tmplObjectAddManifest", &objectNode_obj, &id))
    return NULL;

  objectNode = xmlNodePtr_get(PyObject_GetAttr(objectNode_obj, PyString_FromString("_o")));
  manifest = xmlSecTmplObjectAddManifest(objectNode, id);

  return PyCObject_FromVoidPtrAndDesc((void *) manifest, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplManifestAddReference(PyObject *self, PyObject *args) {
  PyObject *manifestNode_obj;
  PyObject *digestMethodId_meth;
  xmlNodePtr manifestNode;
  const xmlChar *id;
  const xmlChar *uri;
  const xmlChar *type;
  xmlNodePtr reference;

  if (!PyArg_ParseTuple(args, "OOzzz:tmplManifestAddReference", &manifestNode_obj,
			&digestMethodId_meth, &id, &uri, &type))
    return NULL;

  manifestNode = xmlNodePtr_get(PyObject_GetAttr(manifestNode_obj, PyString_FromString("_o")));
  reference = xmlSecTmplManifestAddReference(manifestNode,
				       PyCObject_AsVoidPtr(digestMethodId_meth),
				       id, uri, type);

  return PyCObject_FromVoidPtrAndDesc((void *) reference, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddKeyName(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  const xmlChar *name;
  xmlNodePtr keyName;

  if (!PyArg_ParseTuple(args, "Oz:tmplKeyInfoAddKeyName", &keyInfoNode_obj, &name))
    return NULL;

  keyInfoNode = xmlNodePtr_get(PyObject_GetAttr(keyInfoNode_obj, PyString_FromString("_o")));
  keyName = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, name);

  return PyCObject_FromVoidPtrAndDesc((void *) keyName, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddKeyValue(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr keyValue;

  if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddKeyValue", &keyInfoNode_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(PyObject_GetAttr(keyInfoNode_obj, PyString_FromString("_o")));
  keyValue = xmlSecTmplKeyInfoAddKeyValue(keyInfoNode);

  return PyCObject_FromVoidPtrAndDesc((void *) keyValue, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddX509Data(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr X509Data;

  if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddX509Data", &keyInfoNode_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(PyObject_GetAttr(keyInfoNode_obj, PyString_FromString("_o")));
  X509Data = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);

  return PyCObject_FromVoidPtrAndDesc((void *) X509Data, (char *) "xmlNodePtr", NULL);
}
