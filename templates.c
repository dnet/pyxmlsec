/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
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

#include "wrap_objs.h"

#include "templates.h"

PyObject *xmlsec_TmplSignatureCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *c14nMethodId_meth, *signMethodId_meth;
  xmlDocPtr doc;
  const xmlChar *id = NULL;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, "OOOz:tmplSignatureCreate", &doc_obj,
			&c14nMethodId_meth, &signMethodId_meth, &id))
    return NULL;
  
  if (!PyInstance_Check(doc_obj)) {
    PyErr_SetString(xmlsec_error,
		    "tmplSignatureCreate() argument 1 must be an instance");
    return NULL;
  }

  doc = xmlDocPtr_get(doc_obj);
  node = xmlSecTmplSignatureCreate(doc,
				   PyCObject_AsVoidPtr(c14nMethodId_meth),
				   PyCObject_AsVoidPtr(signMethodId_meth), id);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id = NULL;
  xmlNodePtr eki;

  if (!PyArg_ParseTuple(args, "Oz:tmplSignatureEnsureKeyInfo", &signNode_obj, &id))
    return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  eki = xmlSecTmplSignatureEnsureKeyInfo(signNode, id);
  return PyCObject_FromVoidPtrAndDesc((void *) eki, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureAddReference(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  PyObject *digestMethodId_meth;
  xmlNodePtr signNode;
  const xmlChar *id = NULL;
  const xmlChar *uri = NULL;
  const xmlChar *type = NULL;
  xmlNodePtr ref;

  if (!PyArg_ParseTuple(args, "OOzzz:tmplSignatureAddReference", &signNode_obj,
			&digestMethodId_meth, &id, &uri, &type))
    return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  ref = xmlSecTmplSignatureAddReference(signNode,
					PyCObject_AsVoidPtr(digestMethodId_meth),
					id, uri, type);
  return PyCObject_FromVoidPtrAndDesc((void *) ref, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureAddObject(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id = NULL;
  const xmlChar *mimeType = NULL;
  const xmlChar *encoding = NULL;
  xmlNodePtr obj;

  if (!PyArg_ParseTuple(args, "Ozzz:tmplSignatureAddObject", &signNode_obj,
			&id, &mimeType, &encoding))
    return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  obj = xmlSecTmplSignatureAddObject(signNode, id, mimeType, encoding);

  return PyCObject_FromVoidPtrAndDesc((void *) obj, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureGetSignMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, "O:tmplSignatureGetSignMethodNode", &signNode_obj))
    return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  node = xmlSecTmplSignatureGetSignMethodNode(signNode);
  
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplSignatureGetC14NMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;
  
  if (!PyArg_ParseTuple(args, "O:tmplSignatureGetC14NMethodNode", &signNode_obj))
    return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
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

  referenceNode = xmlNodePtr_get(referenceNode_obj);
  transform = xmlSecTmplReferenceAddTransform(referenceNode,
					  PyCObject_AsVoidPtr(transformId_meth));
  return PyCObject_FromVoidPtrAndDesc((void *) transform, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplObjectAddSignProperties(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id = NULL;
  const xmlChar *target = NULL;
  xmlNodePtr signProperties;

  if (!PyArg_ParseTuple(args, "Ozz:tmplObjectAddSignProperties", &objectNode_obj, &id, &target))
    return NULL;

  objectNode = xmlNodePtr_get(objectNode_obj);
  signProperties = xmlSecTmplObjectAddSignProperties(objectNode, id, target);

  return PyCObject_FromVoidPtrAndDesc((void *) signProperties, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplObjectAddManifest(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id = NULL;
  xmlNodePtr manifest;

  if (!PyArg_ParseTuple(args, "Oz:tmplObjectAddManifest", &objectNode_obj, &id))
    return NULL;

  objectNode = xmlNodePtr_get(objectNode_obj);
  manifest = xmlSecTmplObjectAddManifest(objectNode, id);

  return PyCObject_FromVoidPtrAndDesc((void *) manifest, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplManifestAddReference(PyObject *self, PyObject *args) {
  PyObject *manifestNode_obj;
  PyObject *digestMethodId_meth;
  xmlNodePtr manifestNode;
  const xmlChar *id = NULL;
  const xmlChar *uri = NULL;
  const xmlChar *type = NULL;
  xmlNodePtr reference;

  if (!PyArg_ParseTuple(args, "OOzzz:tmplManifestAddReference", &manifestNode_obj,
			&digestMethodId_meth, &id, &uri, &type))
    return NULL;

  manifestNode = xmlNodePtr_get(manifestNode_obj);
  reference = xmlSecTmplManifestAddReference(manifestNode,
				       PyCObject_AsVoidPtr(digestMethodId_meth),
				       id, uri, type);

  return PyCObject_FromVoidPtrAndDesc((void *) reference, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *encMethodId_meth;
  xmlDocPtr doc = NULL;
  const xmlChar *id = NULL;
  const xmlChar *type = NULL;
  const xmlChar *mimeType = NULL;
  const xmlChar *encoding = NULL;
  xmlNodePtr encDataNode;

  if (!PyArg_ParseTuple(args, "OOzzzz:tmplEncDataCreate", &doc_obj,
			&encMethodId_meth, &id, &type, &mimeType, &encoding))
    return NULL;

  if (doc_obj != Py_None) {
    doc = xmlDocPtr_get(doc_obj);
  }
  encDataNode = xmlSecTmplEncDataCreate(doc, PyCObject_AsVoidPtr(encMethodId_meth),
					id, type, mimeType, encoding);

  if (encDataNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) encDataNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  xmlNodePtr keyInfoNode;

  if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureKeyInfo", &encNode_obj, &id))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encNode, id);

  if (keyInfoNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) keyInfoNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataEnsureEncProperties(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  xmlNodePtr encPropNode;

  if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureEncProperties", &encNode_obj, &id))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encPropNode = xmlSecTmplEncDataEnsureEncProperties(encNode, id);

  if (encPropNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) encPropNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataAddEncProperty(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  const xmlChar *target = NULL;
  xmlNodePtr encPropNode;

  if (!PyArg_ParseTuple(args, "Ozz:tmplEncDataAddEncProperty", &encNode_obj,
			&id, &target))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encPropNode = xmlSecTmplEncDataAddEncProperty(encNode, id, target);

  if (encPropNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) encPropNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataEnsureCipherValue(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  xmlNodePtr cipherValNode;

  if (!PyArg_ParseTuple(args, "O:tmplEncDataEnsureCipherValue", &encNode_obj))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  cipherValNode = xmlSecTmplEncDataEnsureCipherValue(encNode);

  if (cipherValNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) cipherValNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataEnsureCipherReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr cipherRefNode;

  if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureCipherReference", &encNode_obj, &uri))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  cipherRefNode = xmlSecTmplEncDataEnsureCipherReference(encNode, uri);

  if (cipherRefNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) cipherRefNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplEncDataGetEncMethodNode(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  xmlNodePtr encMethNode;

  if (!PyArg_ParseTuple(args, "O:tmplEncDataGetEncMethodNode", &encNode_obj))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encMethNode = xmlSecTmplEncDataGetEncMethodNode(encNode);

  if (encMethNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) encMethNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplCipherReferenceAddTransform(PyObject *self, PyObject *args) {
  PyObject *cipherReferenceNode_obj, *transformId_meth;
  xmlNodePtr cipherReferenceNode;
  xmlNodePtr dsigTransNode;

  if (!PyArg_ParseTuple(args, "OO:tmplCipherReferenceAddTransform",
			&cipherReferenceNode_obj, &transformId_meth))
    return NULL;

  cipherReferenceNode = xmlNodePtr_get(cipherReferenceNode_obj);
  dsigTransNode = xmlSecTmplCipherReferenceAddTransform(cipherReferenceNode,
							PyCObject_AsVoidPtr(transformId_meth));
  if (dsigTransNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) dsigTransNode, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplReferenceListAddDataReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr dataRefNode;

  if (!PyArg_ParseTuple(args, "Oz:tmplReferenceListAddDataReference", &encNode_obj, &uri))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  dataRefNode = xmlSecTmplReferenceListAddDataReference(encNode, uri);

  if (dataRefNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) dataRefNode, (char *) "xmlNodePtr", NULL); 
}

PyObject *xmlsec_TmplReferenceListAddKeyReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr keyRefNode;

  if (!PyArg_ParseTuple(args, "Oz:tmplReferenceListAddKeyReference", &encNode_obj, &uri))
    return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  keyRefNode = xmlSecTmplReferenceListAddKeyReference(encNode, uri);

  if (keyRefNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) keyRefNode, (char *) "xmlNodePtr", NULL); 
}

PyObject *xmlsec_TmplKeyInfoAddKeyName(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  const xmlChar *name;
  xmlNodePtr keyName;

  if (!PyArg_ParseTuple(args, "Oz:tmplKeyInfoAddKeyName", &keyInfoNode_obj, &name))
    return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyName = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, name);

  return PyCObject_FromVoidPtrAndDesc((void *) keyName, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddKeyValue(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr keyValue;

  if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddKeyValue", &keyInfoNode_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyValue = xmlSecTmplKeyInfoAddKeyValue(keyInfoNode);

  return PyCObject_FromVoidPtrAndDesc((void *) keyValue, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddX509Data(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr X509Data;

  if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddX509Data", &keyInfoNode_obj))
    return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  X509Data = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);

  return PyCObject_FromVoidPtrAndDesc((void *) X509Data, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_TmplKeyInfoAddEncryptedKey(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *encMethodId_meth;
  xmlNodePtr keyInfoNode;
  xmlSecTransformId encMethodId = NULL;
  const xmlChar *id = NULL;
  const xmlChar *type = NULL;
  const xmlChar *recipient = NULL;
  xmlNodePtr encKeyNode;

  if (!PyArg_ParseTuple(args, "OOzzz:tmplKeyInfoAddEncryptedKey", &keyInfoNode_obj,
			&encMethodId_meth, &id, &type, &recipient))
    return NULL;

  /* the encryption method is optional. */
  if (encMethodId_meth != Py_None) {
    encMethodId = PyCObject_AsVoidPtr(encMethodId_meth);
  }
  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  encKeyNode = xmlSecTmplKeyInfoAddEncryptedKey(keyInfoNode, encMethodId,
						id, type, recipient);

  if (encKeyNode == NULL) {
    Py_INCREF(Py_None);
    return Py_None;
  }
  return PyCObject_FromVoidPtrAndDesc((void *) encKeyNode, (char *) "xmlNodePtr", NULL);
}
