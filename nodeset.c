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

#include "nodeset.h"

PyObject *wrap_xmlSecNodeSetPtr(xmlSecNodeSetPtr nset) {
  PyObject *ret;

  if (nset == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) nset,
				     (char *) "xmlSecNodeSetPtr", NULL);
  return (ret);
}

/*****************************************************************************/

PyObject *xmlSecNodeSet_getattr(PyObject *self, PyObject *args) {
  PyObject *nset_obj;
  xmlSecNodeSetPtr nset;
  const char *attr;

  if (!PyArg_ParseTuple(args, "Os:nodeSetGetAttr",
			&nset_obj, &attr))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssssss]", "nodes", "doc", "destroyDoc", "type",
			 "op", "next", "prev", "children");
  if (!strcmp(attr, "nodes"))
    return (wrap_xmlNodeSetPtr(nset->nodes));
  if (!strcmp(attr, "doc"))
    return (wrap_xmlDocPtr(nset->doc));
  if (!strcmp(attr, "destroyDoc"))
    return (wrap_int(nset->destroyDoc));
  if (!strcmp(attr, "type"))
    return (wrap_int(nset->type));
  if (!strcmp(attr, "op"))
    return (wrap_int(nset->op));
  if (!strcmp(attr, "next"))
    return (wrap_xmlSecNodeSetPtr(nset->next));
  if (!strcmp(attr, "prev"))
    return (wrap_xmlSecNodeSetPtr(nset->prev));
  if (!strcmp(attr, "children"))
    return (wrap_xmlSecNodeSetPtr(nset->children));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecNodeSet_setattr(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *value_obj;
  xmlSecNodeSetPtr nset;
  const char *name;

  if (!PyArg_ParseTuple(args, "OsO:nodeSetSetAttr",
			&nset_obj, &name, &value_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
    
  if (!strcmp(name, "nodes"))
    nset->nodes = xmlNodeSetPtr_get(value_obj);
  else if (!strcmp(name, "doc"))
    nset->doc = xmlDocPtr_get(value_obj);
  else if (!strcmp(name, "destroyDoc"))
    nset->destroyDoc = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "type"))
    nset->type = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "op"))
    nset->op = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "next"))
    nset->next = xmlSecNodeSetPtr_get(value_obj);
  else if (!strcmp(name, "prev"))
    nset->prev = xmlSecNodeSetPtr_get(value_obj);
  else if (!strcmp(name, "children"))
    nset->children = xmlSecNodeSetPtr_get(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/*****************************************************************************/

PyObject *xmlsec_NodeSetCreate(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *nodes_obj;
  xmlDocPtr doc;
  xmlNodeSetPtr nodes;
  xmlSecNodeSetType type;

  if (!PyArg_ParseTuple(args, "OOi:nodeSetCreate", &doc_obj, &nodes_obj, &type))
    return NULL;

  doc = xmlDocPtr_get(doc_obj);
  nodes = xmlNodeSetPtr_get(nodes_obj);

  return (wrap_xmlSecNodeSetPtr(xmlSecNodeSetCreate(doc, nodes, type)));
}

PyObject *xmlsec_NodeSetDestroy(PyObject *self, PyObject *args) {
  PyObject *nset_obj;
  xmlSecNodeSetPtr nset;

  if (!PyArg_ParseTuple(args, "O:nodeSetDestroy", &nset_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  xmlSecNodeSetDestroy(nset);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_NodeSetDocDestroy(PyObject *self, PyObject *args) {
  PyObject *nset_obj;
  xmlSecNodeSetPtr nset;

  if (!PyArg_ParseTuple(args, "O:nodeSetDocDestroy", &nset_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  xmlSecNodeSetDocDestroy(nset);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_NodeSetContains(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *node_obj, *parent_obj;
  xmlSecNodeSetPtr nset;
  xmlNodePtr node;
  xmlNodePtr parent;

  if (!PyArg_ParseTuple(args, "OOO:nodeSetContains", &nset_obj, &node_obj,
			&parent_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  node = xmlNodePtr_get(node_obj);
  parent = xmlNodePtr_get(parent_obj);

  return (wrap_int(xmlSecNodeSetContains(nset, node, parent)));
}

PyObject *xmlsec_NodeSetAdd(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *newNSet_obj;
  xmlSecNodeSetPtr nset;
  xmlSecNodeSetPtr newNSet;
  xmlSecNodeSetOp op;

  if (!PyArg_ParseTuple(args, "OOi:nodeSetAdd", &nset_obj, &newNSet_obj, &op))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  newNSet = xmlSecNodeSetPtr_get(newNSet_obj);

  return (wrap_xmlSecNodeSetPtr(xmlSecNodeSetAdd(nset, newNSet, op)));
}

PyObject *xmlsec_NodeSetAddList(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *newNSet_obj;
  xmlSecNodeSetPtr nset;
  xmlSecNodeSetPtr newNSet;
  xmlSecNodeSetOp op;

  if (!PyArg_ParseTuple(args, "OOi:nodeSetAddList", &nset_obj, &newNSet_obj, &op))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  newNSet = xmlSecNodeSetPtr_get(newNSet_obj);

  return (wrap_xmlSecNodeSetPtr(xmlSecNodeSetAddList(nset, newNSet, op)));
}

PyObject *xmlsec_NodeSetGetChildren(PyObject *self, PyObject *args) {
  PyObject *doc_obj, *parent_obj;
  xmlDocPtr doc;
  xmlNodePtr parent = NULL;
  int withComments, invert;
  xmlSecNodeSetPtr cnset;

  if (!PyArg_ParseTuple(args, "OOii:nodeSetGetChildren", &doc_obj, &parent_obj,
			&withComments, &invert))
    return NULL;

  doc = xmlDocPtr_get(doc_obj);
  /* parent may be NULL */
  if (parent_obj != Py_None) {
    parent = xmlNodePtr_get(parent_obj);
  }
  cnset = xmlSecNodeSetGetChildren(doc, parent, withComments, invert);

  return (wrap_xmlSecNodeSetPtr(cnset));
}

PyObject *xmlsec_NodeSetWalk(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *walkFunc_obj, *data_obj;
  xmlSecNodeSetPtr nset;
  int ret;

  if (!PyArg_ParseTuple(args, "OOO:nodeSetWalk", &nset_obj, &walkFunc_obj,
			&data_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  ret = xmlSecNodeSetWalk(nset, PyCObject_AsVoidPtr(walkFunc_obj),
			  PyCObject_AsVoidPtr(data_obj));

  return (wrap_int(ret));
}

PyObject *xmlsec_NodeSetDumpTextNodes(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *out_obj;
  xmlSecNodeSetPtr nset;
  xmlOutputBufferPtr out;
  int ret;

  if (!PyArg_ParseTuple(args, "OO:nodeSetDumpTextNodes", &nset_obj, &out_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  out = xmlOutputBufferPtr_get(out_obj);
  ret = xmlSecNodeSetDumpTextNodes(nset, out);

  return (wrap_int(ret));
}

PyObject *xmlsec_NodeSetDebugDump(PyObject *self, PyObject *args) {
  PyObject *nset_obj, *output_obj;
  xmlSecNodeSetPtr nset;
  FILE *output;

  if (!PyArg_ParseTuple(args, "OO:nodeSetDebugDump", &nset_obj, &output_obj))
    return NULL;

  nset = xmlSecNodeSetPtr_get(nset_obj);
  output = PyFile_get(output_obj);
  xmlSecNodeSetDebugDump(nset, output);

  Py_INCREF(Py_None);
  return (Py_None);
}
