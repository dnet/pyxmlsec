/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
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

#include "xmltree.h"

PyObject *xmlsec_NodeGetName(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "O:NodeGetName", &node_obj))
    return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_charPtrConst(xmlSecNodeGetName(node)));
}

PyObject *xmlsec_GetNodeNsHref(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;

  if(!PyArg_ParseTuple(args, (char *) "O:getNodeNsHref", &cur_obj))
    return NULL;

  cur = xmlNodePtr_get(cur_obj);

  return (wrap_xmlCharPtrConst(xmlSecGetNodeNsHref(cur)));
}

PyObject *xmlsec_CheckNodeName(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  const xmlChar *name;
  const xmlChar *ns;

  if(!PyArg_ParseTuple(args, (char *) "Osz:checkNodeName",
		       &cur_obj, &name, &ns))
    return NULL;

  cur = xmlNodePtr_get(cur_obj);

  return (wrap_int(xmlSecCheckNodeName(cur, name, ns)));
}

PyObject *xmlsec_GetNextElementNode(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "O:getNextElementNode", &cur_obj))
    return NULL;

  cur = xmlNodePtr_get(cur_obj);
  node = xmlSecGetNextElementNode(cur);

  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_FindChild(PyObject *self, PyObject *args) {
  PyObject *parent_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:findChild",
		       &parent_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(parent_obj)) {
    PyErr_SetString(xmlsec_error, "findChild() argument 1 must be an instance");
    return NULL;
  }

  parent = xmlNodePtr_get(parent_obj);
  node = xmlSecFindChild(parent, name, ns);

  return (wrap_xmlNodePtr(node));
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

  cur = xmlNodePtr_get(cur_obj);
  node = xmlSecFindParent(cur, name, ns);

  return (wrap_xmlNodePtr(node));
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
    PyErr_SetString(xmlsec_error,
    		    "findNode() argument 1 must be an xmlNode instance");
    return NULL;
  }

  parent = xmlNodePtr_get(parent_obj);
  node = xmlSecFindNode(parent, name, ns);

  return (wrap_xmlNodePtr(node));
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

  parent = xmlNodePtr_get(parent_obj);
  node = xmlSecAddChild(parent, name, ns);

  return (wrap_xmlNodePtr(node));
}

PyObject *xmlsec_AddNextSibling(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr node;
  xmlNodePtr new_node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:addNextSibling",
		       &node_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(node_obj)) {
    PyErr_SetString(xmlsec_error, "addNextSibling() argument 1 must be an instance");
    return NULL;
  }

  node = xmlNodePtr_get(node_obj);
  new_node = xmlSecAddNextSibling(node, name, ns);

  return (wrap_xmlNodePtr(new_node));
}

PyObject *xmlsec_AddPrevSibling(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr node;
  xmlNodePtr new_node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:addPrevSibling",
		       &node_obj, &name, &ns))
    return NULL;

  if (!PyInstance_Check(node_obj)) {
    PyErr_SetString(xmlsec_error, "addPrevSibling() argument 1 must be an instance");
    return NULL;
  }

  node = xmlNodePtr_get(node_obj);
  new_node = xmlSecAddPrevSibling(node, name, ns);

  return (wrap_xmlNodePtr(new_node));
}

PyObject *xmlsec_ReplaceNode(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if(!PyArg_ParseTuple(args, (char *) "OO:replaceNode",
		       &node_obj, &newNode_obj))
    return NULL;

  node = xmlNodePtr_get(node_obj);
  newNode = xmlNodePtr_get(newNode_obj);

  return (wrap_int(xmlSecReplaceNode(node, newNode)));
}

PyObject *xmlsec_ReplaceContent(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if(!PyArg_ParseTuple(args, (char *) "OO:replaceContent",
		       &node_obj, &newNode_obj))
    return NULL;

  node = xmlNodePtr_get(node_obj);
  newNode = xmlNodePtr_get(newNode_obj);

  return (wrap_int(xmlSecReplaceContent(node, newNode)));
}

PyObject *xmlsec_ReplaceNodeBuffer(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;
  const xmlSecByte *buffer;
  xmlSecSize size;

  if(!PyArg_ParseTuple(args, (char *) "Osi:replaceNodeBuffer",
		       &node_obj, &buffer, &size))
    return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecReplaceNodeBuffer(node, buffer, size)));
}

PyObject *xmlsec_AddIDs(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *cur_obj, *ids_obj;
  xmlDocPtr doc;
  xmlNodePtr cur;
  xmlChar **ids = NULL;

  if (!PyArg_ParseTuple(args, (char *) "OOO:addIDs",
			&doc_obj, &cur_obj, &ids_obj))
    return NULL;

  doc = xmlDocPtr_get(doc_obj);
  cur = xmlNodePtr_get(cur_obj);
  ids = PyStringList_AsCharPtrPtr(ids_obj);

  xmlSecAddIDs(doc, cur, (const xmlChar **)ids);
  xmlFree(ids);
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_CreateTree(PyObject *self, PyObject *args) {
  const xmlChar *rootNodeName;
  const xmlChar *rootNodeNs;
  xmlDocPtr tree;

  if (!PyArg_ParseTuple(args, (char *) "sz:createTree",
			&rootNodeName, &rootNodeNs))
    return NULL;

  tree = xmlSecCreateTree(rootNodeName, rootNodeNs);

  return (wrap_xmlDocPtr(tree));
}

PyObject *xmlsec_IsEmptyNode(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if (!PyArg_ParseTuple(args, (char *) "O:isEmptyNode", &node_obj))
    return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecIsEmptyNode(node)));
}

PyObject *xmlsec_IsEmptyString(PyObject *self, PyObject *args) {
  const xmlChar *str;

  if (!PyArg_ParseTuple(args, (char *) "s:isEmptyString", &str))
    return NULL;

  return (wrap_int(xmlSecIsEmptyString(str)));
}

PyObject *xmlsec_IsHex(PyObject *self, PyObject *args) {
  char c;

  if (!PyArg_ParseTuple(args, (char *) "c:isHex", &c))
    return NULL;

  return (wrap_int(xmlSecIsHex(c)));
}

PyObject *xmlsec_GetHex(PyObject *self, PyObject *args) {
  char c;

  if (!PyArg_ParseTuple(args, (char *) "c:getHex", &c))
    return NULL;

  return (wrap_int(xmlSecGetHex(c)));
}
