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

#include "xmlsecmod.h"
#include "xmltree.h"

PyObject *xmlsec_NodeGetName(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "O:NodeGetName", &node_obj))
    return NULL;
  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  return Py_BuildValue("s", xmlSecNodeGetName(node));
}

PyObject *xmlsec_GetNodeNsHref(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;

  if(!PyArg_ParseTuple(args, (char *) "O:getNodeNsHref", &cur_obj))
    return NULL;
  cur = xmlNodePtr_get(PyObject_GetAttr(cur_obj, PyString_FromString("_o")));
  return Py_BuildValue("s", xmlSecGetNodeNsHref(cur));
}

PyObject *xmlsec_CheckNodeName(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  const xmlChar *name;
  const xmlChar *ns;

  if(!PyArg_ParseTuple(args, (char *) "Osz:checkNodeName", &cur_obj, &name, &ns))
    return NULL;
  cur = xmlNodePtr_get(PyObject_GetAttr(cur_obj, PyString_FromString("_o")));
  return Py_BuildValue("i", xmlSecCheckNodeName(cur, name, ns));
}

PyObject *xmlsec_GetNextElementNode(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "O:getNextElementNode", &cur_obj))
    return NULL;
  cur = xmlNodePtr_get(PyObject_GetAttr(cur_obj, PyString_FromString("_o")));
  node = xmlSecGetNextElementNode(cur);

  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_FindChild(PyObject *self, PyObject *args) {
  PyObject *parent_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:findChild", &parent_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(parent_obj)) {
    PyErr_SetString(xmlsec_error, "findChild() argument 1 must be an instance");
    return NULL;
  }

  parent = xmlNodePtr_get(PyObject_GetAttr(parent_obj, PyString_FromString("_o")));
  node = xmlSecFindChild(parent, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_FindParent(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr cur;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:findParent", &cur_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(cur_obj)) {
    PyErr_SetString(xmlsec_error, "findParent() argument 1 must be an instance");
    return NULL;
  }

  cur = xmlNodePtr_get(PyObject_GetAttr(cur_obj, PyString_FromString("_o")));
  node = xmlSecFindParent(cur, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_FindNode(PyObject *self, PyObject *args) {
  PyObject *parent_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:findNode", &parent_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(parent_obj)) {
    PyErr_SetString(xmlsec_error, "findNode() argument 1 must be an instance");
    return NULL;
  }

  parent = xmlNodePtr_get(PyObject_GetAttr(parent_obj, PyString_FromString("_o")));
  node = xmlSecFindNode(parent, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_AddChild(PyObject *self, PyObject *args) {
  PyObject *parent_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:addChild", &parent_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(parent_obj)) {
    PyErr_SetString(xmlsec_error, "addChild() argument 1 must be an instance");
    return NULL;
  }

  parent = xmlNodePtr_get(PyObject_GetAttr(parent_obj, PyString_FromString("_o")));
  node = xmlSecAddChild(parent, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_AddNextSibling(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr node;
  xmlNodePtr new_node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:addNextSibling", &node_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(node_obj)) {
    PyErr_SetString(xmlsec_error, "addNextSibling() argument 1 must be an instance");
    return NULL;
  }

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  new_node = xmlSecAddNextSibling(node, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) new_node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_AddPrevSibling(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr node;
  xmlNodePtr new_node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:addPrevSibling", &node_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(node_obj)) {
    PyErr_SetString(xmlsec_error, "addPrevSibling() argument 1 must be an instance");
    return NULL;
  }

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  new_node = xmlSecAddPrevSibling(node, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) new_node, (char *) "xmlNodePtr", NULL);
}

PyObject *xmlsec_ReplaceNode(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if(!PyArg_ParseTuple(args, (char *) "OO:replaceNode", &node_obj, &newNode_obj))
    return NULL;

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  newNode = xmlNodePtr_get(PyObject_GetAttr(newNode_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", xmlSecReplaceNode(node, newNode));
}

PyObject *xmlsec_ReplaceContent(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if(!PyArg_ParseTuple(args, (char *) "OO:replaceContent", &node_obj, &newNode_obj))
    return NULL;

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));
  newNode = xmlNodePtr_get(PyObject_GetAttr(newNode_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", xmlSecReplaceContent(node, newNode));
}

PyObject *xmlsec_ReplaceNodeBuffer(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;
  const xmlSecByte *buffer;
  xmlSecSize size;

  if(!PyArg_ParseTuple(args, (char *) "Osi:replaceNodeBuffer",
		       &node_obj, &buffer, &size))
    return NULL;

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", xmlSecReplaceNodeBuffer(node, buffer, size));
}

PyObject *xmlsec_AddIDs(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *cur_obj;
  xmlDocPtr doc;
  xmlNodePtr cur;
  const xmlChar **ids;

  if (!PyArg_ParseTuple(args, (char *) "OOs:addIDs", &doc_obj, &cur_obj, &ids))
    return NULL;

  doc = xmlDocPtr_get(PyObject_GetAttr(doc_obj, PyString_FromString("_o")));
  cur = xmlNodePtr_get(PyObject_GetAttr(cur_obj, PyString_FromString("_o")));

  // ids should be a list (NULL terminated)
  xmlSecAddIDs(doc, cur, ids);

  Py_INCREF(Py_None);
  return Py_None;
}

PyObject *xmlsec_CreateTree(PyObject *self, PyObject *args) {
  const xmlChar *rootNodeName;
  const xmlChar *rootNodeNs;
  xmlDocPtr tree;

  if (!PyArg_ParseTuple(args, (char *) "sz:createTree", &rootNodeName, &rootNodeNs))
    return NULL;

  tree = xmlSecCreateTree(rootNodeName, rootNodeNs);
  return PyCObject_FromVoidPtrAndDesc((void *) tree, (char *) "xmlDocPtr", NULL);
}

PyObject *xmlsec_IsEmptyNode(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, (char *) "O:isEmptyNode", &node_obj))
    return NULL;

  node = xmlNodePtr_get(PyObject_GetAttr(node_obj, PyString_FromString("_o")));

  return Py_BuildValue("i", xmlSecIsEmptyNode(node));
}

PyObject *xmlsec_IsEmptyString(PyObject *self, PyObject *args) {
  const xmlChar *str;

  if (!PyArg_ParseTuple(args, (char *) "s:isEmptyString", &str))
    return NULL;

  return Py_BuildValue("i", xmlSecIsEmptyString(str));
}

PyObject *xmlsec_IsHex(PyObject *self, PyObject *args) {
  char c;

  if (!PyArg_ParseTuple(args, (char *) "c:isHex", &c))
    return NULL;

  return Py_BuildValue("i", xmlSecIsHex(c));
}

PyObject *xmlsec_GetHex(PyObject *self, PyObject *args) {
  char c;

  if (!PyArg_ParseTuple(args, (char *) "c:getHex", &c))
    return NULL;

  return Py_BuildValue("i", xmlSecGetHex(c));
}
