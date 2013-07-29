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

#include "templates.h"
#include "transforms.h"

PyObject *xmlsec_TmplSignatureCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *c14nMethodId_obj, *signMethodId_obj;
  xmlDocPtr doc = NULL;
  xmlSecTransformId c14nMethodId;
  xmlSecTransformId signMethodId;
  const xmlChar *id = NULL;
  xmlNodePtr node;
  
  if (CheckArgs(args, "oOOs:tmplSignatureCreate")) {
    if (!PyArg_ParseTuple(args, "OOOz:tmplSignatureCreate", &doc_obj,
			  &c14nMethodId_obj, &signMethodId_obj, &id))
      return NULL;
  }
  else return NULL;
    
  doc = xmlDocPtr_get(doc_obj);
  c14nMethodId = xmlSecTransformId_get(c14nMethodId_obj);
  signMethodId = xmlSecTransformId_get(signMethodId_obj);

  node = xmlSecTmplSignatureCreate(doc, c14nMethodId, signMethodId, id);

  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_TmplSignatureEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id = NULL;
  xmlNodePtr eki;

  if (CheckArgs(args, "Os:tmplSignatureEnsureKeyInfo")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplSignatureEnsureKeyInfo",
			  &signNode_obj, &id))
      return NULL;
  }
  else return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  eki = xmlSecTmplSignatureEnsureKeyInfo(signNode, id);

  return (wrap_xmlNodePtr(eki));
}

PyObject *xmlsec_TmplSignatureAddReference(PyObject *self, PyObject *args) {
  PyObject *signNode_obj, *digestMethodId_obj;
  xmlNodePtr signNode;
  xmlSecTransformId digestMethodId;
  const xmlChar *id = NULL;
  const xmlChar *uri = NULL;
  const xmlChar *type = NULL;
  xmlNodePtr ref;

  if (CheckArgs(args, "OOsss:tmplSignatureAddReference")) {
    if (!PyArg_ParseTuple(args, "OOzzz:tmplSignatureAddReference",
			  &signNode_obj, &digestMethodId_obj,
			  &id, &uri, &type))
      return NULL;
  }
  else return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  digestMethodId = xmlSecTransformId_get(digestMethodId_obj);
  ref = xmlSecTmplSignatureAddReference(signNode, digestMethodId,
					id, uri, type);

  return (wrap_xmlNodePtr(ref));
}

PyObject *xmlsec_TmplSignatureAddObject(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  const xmlChar *id = NULL;
  const xmlChar *mimeType = NULL;
  const xmlChar *encoding = NULL;
  xmlNodePtr obj;

  if (CheckArgs(args, "Osss:tmplSignatureAddObject")) {
    if (!PyArg_ParseTuple(args, "Ozzz:tmplSignatureAddObject", &signNode_obj,
			&id, &mimeType, &encoding))
      return NULL;
  }
  else return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  obj = xmlSecTmplSignatureAddObject(signNode, id, mimeType, encoding);

  return (wrap_xmlNodePtr(obj));
}

PyObject *xmlsec_TmplSignatureGetSignMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;

  if (CheckArgs(args, "O:tmplSignatureGetSignMethodNode")) {
    if (!PyArg_ParseTuple(args, "O:tmplSignatureGetSignMethodNode",
			  &signNode_obj))
      return NULL;
  }
  else return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  node = xmlSecTmplSignatureGetSignMethodNode(signNode);
  
  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_TmplSignatureGetC14NMethodNode(PyObject *self, PyObject *args) {
  PyObject * signNode_obj;
  xmlNodePtr signNode;
  xmlNodePtr node;
  
  if (CheckArgs(args, "O:tmplSignatureGetC14NMethodNode")) {
    if (!PyArg_ParseTuple(args, "O:tmplSignatureGetC14NMethodNode",
			  &signNode_obj))
      return NULL;
  }
  else return NULL;

  signNode = xmlNodePtr_get(signNode_obj);
  node = xmlSecTmplSignatureGetC14NMethodNode(signNode);
  
  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_TmplReferenceAddTransform(PyObject *self, PyObject *args) {
  PyObject *referenceNode_obj, *transformId_obj;
  xmlNodePtr referenceNode;
  xmlSecTransformId transformId;
  xmlNodePtr transform;

  if (CheckArgs(args, "OO:tmplReferenceAddTransform")) {
    if (!PyArg_ParseTuple(args, "OO:tmplReferenceAddTransform",
			  &referenceNode_obj, &transformId_obj))
      return NULL;
  }
  else return NULL;

  referenceNode = xmlNodePtr_get(referenceNode_obj);
  transformId = xmlSecTransformId_get(transformId_obj);
  transform = xmlSecTmplReferenceAddTransform(referenceNode, transformId);

  return (wrap_xmlNodePtr(transform));
}

PyObject *xmlsec_TmplObjectAddSignProperties(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id = NULL;
  const xmlChar *target = NULL;
  xmlNodePtr signProperties;

  if (CheckArgs(args, "Oss:tmplObjectAddSignProperties")) {
    if (!PyArg_ParseTuple(args, "Ozz:tmplObjectAddSignProperties",
			  &objectNode_obj, &id, &target))
    return NULL;
  }
  else return NULL;

  objectNode = xmlNodePtr_get(objectNode_obj);
  signProperties = xmlSecTmplObjectAddSignProperties(objectNode, id, target);

  return (wrap_xmlNodePtr(signProperties));
}

PyObject *xmlsec_TmplObjectAddManifest(PyObject *self, PyObject *args) {
  PyObject *objectNode_obj;
  xmlNodePtr objectNode;
  const xmlChar *id = NULL;
  xmlNodePtr manifest;

  if (CheckArgs(args, "Os:tmplObjectAddManifest")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplObjectAddManifest", &objectNode_obj,
			  &id))
      return NULL;
  }
  else return NULL;

  objectNode = xmlNodePtr_get(objectNode_obj);
  manifest = xmlSecTmplObjectAddManifest(objectNode, id);

  return (wrap_xmlNodePtr(manifest));
}

PyObject *xmlsec_TmplManifestAddReference(PyObject *self, PyObject *args) {
  PyObject *manifestNode_obj, *digestMethodId_obj;
  xmlNodePtr manifestNode;
  xmlSecTransformId digestMethodId;
  const xmlChar *id = NULL;
  const xmlChar *uri = NULL;
  const xmlChar *type = NULL;
  xmlNodePtr reference;

  if (CheckArgs(args, "OOsss:tmplManifestAddReference")) {
    if (!PyArg_ParseTuple(args, "OOzzz:tmplManifestAddReference",
			  &manifestNode_obj, &digestMethodId_obj,
			  &id, &uri, &type))
      return NULL;
  }
  else return NULL;

  manifestNode = xmlNodePtr_get(manifestNode_obj);
  digestMethodId = xmlSecTransformId_get(digestMethodId_obj);
  reference = xmlSecTmplManifestAddReference(manifestNode, digestMethodId,
					     id, uri, type);

  return (wrap_xmlNodePtr(reference));
}

PyObject *xmlsec_TmplEncDataCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *encMethodId_obj;
  xmlDocPtr doc = NULL;
  xmlSecTransformId encMethodId = NULL;
  const xmlChar *id = NULL;
  const xmlChar *type = NULL;
  const xmlChar *mimeType = NULL;
  const xmlChar *encoding = NULL;
  xmlNodePtr encDataNode;

  if (CheckArgs(args, "oossss:tmplEncDataCreate")) {
    if (!PyArg_ParseTuple(args, "OOzzzz:tmplEncDataCreate", &doc_obj,
			  &encMethodId_obj, &id, &type, &mimeType, &encoding))
      return NULL;
  }
  else return NULL;

  doc = xmlDocPtr_get(doc_obj);
  encMethodId = xmlSecTransformId_get(encMethodId_obj);
  encDataNode = xmlSecTmplEncDataCreate(doc, encMethodId,
					id, type, mimeType, encoding);

  return (wrap_xmlNodePtr(encDataNode));
}

PyObject *xmlsec_TmplEncDataEnsureKeyInfo(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  xmlNodePtr keyInfoNode;

  if (CheckArgs(args, "Os:tmplEncDataEnsureKeyInfo")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureKeyInfo", &encNode_obj,
			  &id))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  keyInfoNode = xmlSecTmplEncDataEnsureKeyInfo(encNode, id);

  return (wrap_xmlNodePtr(keyInfoNode));
}

PyObject *xmlsec_TmplEncDataEnsureEncProperties(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  xmlNodePtr encPropNode;

  if (CheckArgs(args, "Os:tmplEncDataEnsureEncProperties")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureEncProperties",
			  &encNode_obj, &id))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encPropNode = xmlSecTmplEncDataEnsureEncProperties(encNode, id);

  return (wrap_xmlNodePtr(encPropNode));
}

PyObject *xmlsec_TmplEncDataAddEncProperty(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *id = NULL;
  const xmlChar *target = NULL;
  xmlNodePtr encPropNode;

  if (CheckArgs(args, "Oss:tmplEncDataAddEncProperty")) {
    if (!PyArg_ParseTuple(args, "Ozz:tmplEncDataAddEncProperty", &encNode_obj,
			  &id, &target))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encPropNode = xmlSecTmplEncDataAddEncProperty(encNode, id, target);

  return (wrap_xmlNodePtr(encPropNode));
}

PyObject *xmlsec_TmplEncDataEnsureCipherValue(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  xmlNodePtr cipherValNode;

  if (CheckArgs(args, "O:tmplEncDataEnsureCipherValue")) {
    if (!PyArg_ParseTuple(args, "O:tmplEncDataEnsureCipherValue", &encNode_obj))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  cipherValNode = xmlSecTmplEncDataEnsureCipherValue(encNode);

  return (wrap_xmlNodePtr(cipherValNode));
}

PyObject *xmlsec_TmplEncDataEnsureCipherReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr cipherRefNode;

  if (CheckArgs(args, "Os:tmplEncDataEnsureCipherReference")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplEncDataEnsureCipherReference",
			  &encNode_obj, &uri))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  cipherRefNode = xmlSecTmplEncDataEnsureCipherReference(encNode, uri);

  return (wrap_xmlNodePtr(cipherRefNode));
}

PyObject *xmlsec_TmplEncDataGetEncMethodNode(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  xmlNodePtr encMethNode;

  if (CheckArgs(args, "O:tmplEncDataGetEncMethodNode")) {
    if (!PyArg_ParseTuple(args, "O:tmplEncDataGetEncMethodNode", &encNode_obj))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  encMethNode = xmlSecTmplEncDataGetEncMethodNode(encNode);

  return (wrap_xmlNodePtr(encMethNode));
}

PyObject *xmlsec_TmplCipherReferenceAddTransform(PyObject *self, PyObject *args) {
  PyObject *cipherReferenceNode_obj, *transformId_obj;
  xmlNodePtr cipherReferenceNode;
  xmlSecTransformId transformId;
  xmlNodePtr dsigTransNode;

  if (CheckArgs(args, "OO:tmplCipherReferenceAddTransform")) {
    if (!PyArg_ParseTuple(args, "OO:tmplCipherReferenceAddTransform",
			  &cipherReferenceNode_obj, &transformId_obj))
      return NULL;
  }
  else return NULL;

  cipherReferenceNode = xmlNodePtr_get(cipherReferenceNode_obj);
  transformId = xmlSecTransformId_get(transformId_obj);
  dsigTransNode = xmlSecTmplCipherReferenceAddTransform(cipherReferenceNode,
							transformId);

  return (wrap_xmlNodePtr(dsigTransNode));
}

PyObject *xmlsec_TmplReferenceListAddDataReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr dataRefNode;

  if (CheckArgs(args, "Os:tmplReferenceListAddDataReference")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplReferenceListAddDataReference",
			  &encNode_obj, &uri))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  dataRefNode = xmlSecTmplReferenceListAddDataReference(encNode, uri);

  return (wrap_xmlNodePtr(dataRefNode));
}

PyObject *xmlsec_TmplReferenceListAddKeyReference(PyObject *self, PyObject *args) {
  PyObject *encNode_obj;
  xmlNodePtr encNode;
  const xmlChar *uri = NULL;
  xmlNodePtr keyRefNode;

  if (CheckArgs(args, "Os:tmplReferenceListAddKeyReference")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplReferenceListAddKeyReference",
			  &encNode_obj, &uri))
      return NULL;
  }
  else return NULL;

  encNode = xmlNodePtr_get(encNode_obj);
  keyRefNode = xmlSecTmplReferenceListAddKeyReference(encNode, uri);

  return (wrap_xmlNodePtr(keyRefNode));
}

PyObject *xmlsec_TmplKeyInfoAddKeyName(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  const xmlChar *name;
  xmlNodePtr keyName;

  if (CheckArgs(args, "Os:tmplKeyInfoAddKeyName")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplKeyInfoAddKeyName",
			  &keyInfoNode_obj, &name))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyName = xmlSecTmplKeyInfoAddKeyName(keyInfoNode, name);

  return (wrap_xmlNodePtr(keyName));
}

PyObject *xmlsec_TmplKeyInfoAddKeyValue(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr keyValue;

  if (CheckArgs(args, "O:tmplKeyInfoAddKeyValue")) {
    if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddKeyValue", &keyInfoNode_obj))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  keyValue = xmlSecTmplKeyInfoAddKeyValue(keyInfoNode);

  return (wrap_xmlNodePtr(keyValue));
}

PyObject *xmlsec_TmplKeyInfoAddX509Data(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  xmlNodePtr X509Data;

  if (CheckArgs(args, "O:tmplKeyInfoAddX509Data")) {
    if (!PyArg_ParseTuple(args, "O:tmplKeyInfoAddX509Data", &keyInfoNode_obj))
      return NULL;
  }
  else return NULL;

  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  X509Data = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);

  return (wrap_xmlNodePtr(X509Data));
}

PyObject *xmlsec_TmplKeyInfoAddRetrievalMethod(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj;
  xmlNodePtr keyInfoNode;
  const xmlChar *uri = NULL;
  const xmlChar *type = NULL;
  xmlNodePtr node;

  if (CheckArgs(args, "Oss:tmplKeyInfoAddRetrievalMethod")) {
    if (!PyArg_ParseTuple(args, "Ozz:tmplKeyInfoAddRetrievalMethod",
			  &keyInfoNode_obj, &uri, &type))
      return NULL;
  }
  else return NULL;
  
  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  node = xmlSecTmplKeyInfoAddRetrievalMethod(keyInfoNode, uri, type);

  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_TmplRetrievalMethodAddTransform(PyObject *self, PyObject *args) {
  PyObject *retrMethodNode_obj, *transformId_obj;
  xmlNodePtr retrMethodNode;
  xmlSecTransformId transformId;
  xmlNodePtr node;

  if (CheckArgs(args, "OO:tmplRetrievalMethodAddTransform")) {
    if (!PyArg_ParseTuple(args, "OO:tmplRetrievalMethodAddTransform",
			  &retrMethodNode_obj, &transformId_obj))
      return NULL;
  }
  else return NULL;
  
  retrMethodNode = xmlNodePtr_get(retrMethodNode_obj);
  transformId = xmlSecTransformId_get(transformId_obj);

  node = xmlSecTmplRetrievalMethodAddTransform(retrMethodNode, transformId);

  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_TmplKeyInfoAddEncryptedKey(PyObject *self, PyObject *args) {
  PyObject *keyInfoNode_obj, *encMethodId_obj;
  xmlNodePtr keyInfoNode;
  xmlSecTransformId encMethodId = NULL;
  const xmlChar *id = NULL;
  const xmlChar *type = NULL;
  const xmlChar *recipient = NULL;
  xmlNodePtr encKeyNode;

  if (CheckArgs(args, "Oosss:tmplKeyInfoAddEncryptedKey")) {
    if (!PyArg_ParseTuple(args, "OOzzz:tmplKeyInfoAddEncryptedKey",
			  &keyInfoNode_obj, &encMethodId_obj, &id, &type,
			  &recipient))
      return NULL;
  }
  else return NULL;

  encMethodId = xmlSecTransformId_get(encMethodId_obj);
  keyInfoNode = xmlNodePtr_get(keyInfoNode_obj);
  encKeyNode = xmlSecTmplKeyInfoAddEncryptedKey(keyInfoNode, encMethodId,
						id, type, recipient);

  return (wrap_xmlNodePtr(encKeyNode));
}

PyObject *xmlsec_TmplTransformAddHmacOutputLength(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj;
  xmlNodePtr transformNode;
  xmlSecSize bitsLen;
  int ret;

  if (CheckArgs(args, "OI:tmplTransformAddHmacOutputLength")) {
    if (!PyArg_ParseTuple(args, "Oi:tmplTransformAddHmacOutputLength",
			  &transformNode_obj, &bitsLen))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);

  ret = xmlSecTmplTransformAddHmacOutputLength(transformNode, bitsLen);
  
  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddRsaOaepParam(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj;
  xmlNodePtr transformNode;
  const xmlSecByte *buf;
  xmlSecSize size;
  int ret;

  if (CheckArgs(args, "OS:tmplTransformAddRsaOaepParam")) {
    if (!PyArg_ParseTuple(args, "Os#:tmplTransformAddRsaOaepParam",
			  &transformNode_obj, &buf, &size))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  
  ret = xmlSecTmplTransformAddRsaOaepParam(transformNode, buf, size);
  
  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddXsltStylesheet(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj;
  xmlNodePtr transformNode;
  const xmlChar *xslt;
  int ret;

  if (CheckArgs(args, "OS:tmplTransformAddXsltStylesheet")) {
    if (!PyArg_ParseTuple(args, "Os:tmplTransformAddXsltStylesheet",
			  &transformNode_obj, &xslt))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  
  ret = xmlSecTmplTransformAddXsltStylesheet(transformNode, xslt);
  
  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddC14NInclNamespaces(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj;
  xmlNodePtr transformNode;
  const xmlChar *prefixList = NULL;
  int ret;

  if (CheckArgs(args, "Os:tmplTransformAddC14NInclNamespaces")) {
    if (!PyArg_ParseTuple(args, "Oz:tmplTransformAddC14NInclNamespaces",
			  &transformNode_obj, &prefixList))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  
  ret = xmlSecTmplTransformAddC14NInclNamespaces(transformNode, prefixList);
  
  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddXPath(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj, *nsList_obj;
  xmlNodePtr transformNode;
  const xmlChar *expression;
  xmlChar **nsList = NULL;
  int ret;

  if (CheckArgs(args, "OSo:tmplTransformAddXPath")) {
    if (!PyArg_ParseTuple(args, "OsO:tmplTransformAddXPath",
			  &transformNode_obj, &expression, &nsList_obj))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  /* convert Python string list into C string array */
  nsList = PythonStringList_get(nsList_obj);

  ret = xmlSecTmplTransformAddXPath(transformNode, expression,
				    (const xmlChar **)nsList);
  xmlFree(nsList);
  
  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddXPath2(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj, *nsList_obj;
  xmlNodePtr transformNode;
  const xmlChar *type;
  const xmlChar *expression;
  xmlChar **nsList = NULL;
  int ret;

  if (CheckArgs(args, "OSSo:tmplTransformAddXPath2")) {
    if (!PyArg_ParseTuple(args, "OssO:tmplTransformAddXPath2",
			  &transformNode_obj, &type, &expression, &nsList_obj))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  nsList = PythonStringList_get(nsList_obj);

  ret = xmlSecTmplTransformAddXPath2(transformNode, type, expression,
				     (const xmlChar **)nsList);
  xmlFree(nsList);

  return (wrap_int(ret));
}

PyObject *xmlsec_TmplTransformAddXPointer(PyObject *self, PyObject *args) {
  PyObject *transformNode_obj, *nsList_obj;
  xmlNodePtr transformNode;
  const xmlChar *expression;
  xmlChar **nsList = NULL;
  int ret;

  if (CheckArgs(args, "OSo:tmplTransformAddXPointer")) {
    if (!PyArg_ParseTuple(args, "OsO:tmplTransformAddXPointer",
			  &transformNode_obj, &expression, &nsList_obj))
      return NULL;
  }
  else return NULL;

  transformNode = xmlNodePtr_get(transformNode_obj);
  nsList = PythonStringList_get(nsList_obj);

  ret = xmlSecTmplTransformAddXPointer(transformNode, expression,
				       (const xmlChar **)nsList);
  xmlFree(nsList);
  
  return (wrap_int(ret));
}
