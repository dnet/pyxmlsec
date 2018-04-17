/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
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

#include "xmltree.h"

PyObject *xmlsec_NodeGetName(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if (CheckArgs(args, "O:nodeGetName")) {
    if(!PyArg_ParseTuple(args, (char *) "O:nodeGetName", &node_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_charPtrConst(xmlSecNodeGetName(node)));
}

PyObject *xmlsec_GetNodeNsHref(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;

  if (CheckArgs(args, "O:getNodeNsHref")) {
    if(!PyArg_ParseTuple(args, (char *) "O:getNodeNsHref", &cur_obj))
      return NULL;
  }
  else return NULL;

  cur = xmlNodePtr_get(cur_obj);

  return (wrap_xmlCharPtrConst(xmlSecGetNodeNsHref(cur)));
}

PyObject *xmlsec_CheckNodeName(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  const xmlChar *name;
  const xmlChar *ns;

  if (CheckArgs(args, "OSs:checkNodeName")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:checkNodeName",
			 &cur_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

  cur = xmlNodePtr_get(cur_obj);

  return (wrap_int(xmlSecCheckNodeName(cur, name, ns)));
}

PyObject *xmlsec_GetNextElementNode(PyObject *self, PyObject *args) {
  PyObject *cur_obj;
  xmlNodePtr cur;
  xmlNodePtr node;

  if (CheckArgs(args, "O:getNextElementNode")) {
    if(!PyArg_ParseTuple(args, (char *) "O:getNextElementNode", &cur_obj))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:findChild")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:findChild",
			 &parent_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:findParent")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:findParent",
			 &cur_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:findNode")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:findNode",
			 &parent_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:addChild")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:addChild",
			 &parent_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:addNextSibling")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:addNextSibling",
			 &node_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

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

  if (CheckArgs(args, "OSs:addPrevSibling")) {
    if(!PyArg_ParseTuple(args, (char *) "Osz:addPrevSibling",
			 &node_obj, &name, &ns))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);
  new_node = xmlSecAddPrevSibling(node, name, ns);

  return (wrap_xmlNodePtr(new_node));
}

PyObject *xmlsec_ReplaceNode(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if (CheckArgs(args, "OO:replaceNode")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:replaceNode",
			 &node_obj, &newNode_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);
  newNode = xmlNodePtr_get(newNode_obj);

  return (wrap_int(xmlSecReplaceNode(node, newNode)));
}

PyObject *xmlsec_ReplaceContent(PyObject *self, PyObject *args) {
  PyObject *node_obj, *newNode_obj;
  xmlNodePtr node;
  xmlNodePtr newNode;
  
  if (CheckArgs(args, "OO:replaceContent")) {
    if(!PyArg_ParseTuple(args, (char *) "OO:replaceContent",
			 &node_obj, &newNode_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);
  newNode = xmlNodePtr_get(newNode_obj);

  return (wrap_int(xmlSecReplaceContent(node, newNode)));
}

PyObject *xmlsec_ReplaceNodeBuffer(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;
  const xmlSecByte *buffer;
  xmlSecSize size;

  if (CheckArgs(args, "OSI:replaceNodeBuffer")) {
    if(!PyArg_ParseTuple(args, (char *) "Osi:replaceNodeBuffer",
			 &node_obj, &buffer, &size))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecReplaceNodeBuffer(node, buffer, size)));
}

PyObject *xmlsec_AddIDs(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *cur_obj, *ids_obj;
  xmlDocPtr doc;
  xmlNodePtr cur;
  xmlChar **ids = NULL;

  if (CheckArgs(args, "OOL:addIDs")) {
    if (!PyArg_ParseTuple(args, (char *) "OOO:addIDs",
			  &doc_obj, &cur_obj, &ids_obj))
      return NULL;
  }
  else return NULL;

  doc = xmlDocPtr_get(doc_obj);
  cur = xmlNodePtr_get(cur_obj);
  ids = PythonStringList_get(ids_obj);

  xmlSecAddIDs(doc, cur, (const xmlChar **)ids);
  xmlFree(ids);
  
  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_CreateTree(PyObject *self, PyObject *args) {
  const xmlChar *rootNodeName;
  const xmlChar *rootNodeNs;
  xmlDocPtr tree;

  if (CheckArgs(args, "Ss:createTree")) {
    if (!PyArg_ParseTuple(args, (char *) "sz:createTree",
			  &rootNodeName, &rootNodeNs))
      return NULL;
  }
  else return NULL;

  tree = xmlSecCreateTree(rootNodeName, rootNodeNs);

  return (wrap_xmlDocPtr(tree));
}

PyObject *xmlsec_IsEmptyNode(PyObject *self, PyObject *args) {
  PyObject *node_obj;
  xmlNodePtr node;

  if (CheckArgs(args, "O:isEmptyNode")) {
    if (!PyArg_ParseTuple(args, (char *) "O:isEmptyNode", &node_obj))
      return NULL;
  }
  else return NULL;

  node = xmlNodePtr_get(node_obj);

  return (wrap_int(xmlSecIsEmptyNode(node)));
}

PyObject *xmlsec_IsEmptyString(PyObject *self, PyObject *args) {
  const xmlChar *str;

  if (CheckArgs(args, "S:isEmptyString")) {
    if (!PyArg_ParseTuple(args, (char *) "s:isEmptyString", &str))
      return NULL;
  }
  else return NULL;

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
