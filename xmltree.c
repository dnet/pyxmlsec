#include <xmlsec/xmltree.h>

#include "xmlsecmod.h"
#include "xmltree.h"

PyObject *xmlsec_FindNode(PyObject *self, PyObject *args) {
  PyObject *obj_parent;
  const xmlChar *name;
  const xmlChar *ns;
  xmlNodePtr parent;
  xmlNodePtr node;

  if(!PyArg_ParseTuple(args, (char *) "Oss:findNode", &obj_parent, &name, &ns))
    return NULL;

  if (!PyInstance_Check(obj_parent)) {
    printf("parent isn't an Instance !!!\n");
    return NULL;
  }

  parent = PyxmlNode_Get(PyObject_GetAttr(obj_parent, PyString_FromString("_o")));
  node = xmlSecFindNode((xmlNodePtr)parent, name, ns);
  return PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "xmlNodePtr", NULL);
}
