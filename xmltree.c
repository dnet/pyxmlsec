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

#include <xmlsec/xmltree.h>

#include "xmlsecmod.h"
#include "xmltree.h"

PyObject *xmlsec_FindNode(PyObject *self, PyObject *args) {
  PyObject *obj_parent;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Osz:findNode", &obj_parent, &name, &ns))
    return NULL;

  if (!PyInstance_Check(obj_parent)) {
    printf("parent isn't an Instance !!!\n");
    return NULL;
  }

  parent = PyxmlNode_Get(PyObject_GetAttr(obj_parent, PyString_FromString("_o")));
  node = xmlSecFindNode((xmlNodePtr)parent, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}
