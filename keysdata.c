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

#include "xmlsecmod.h"

#include "keysdata.h"
#include "keys.h"
#include "keyinfo.h"
#include "list.h"

PyObject *wrap_xmlSecKeyDataPtr(xmlSecKeyDataPtr data) {
  PyObject *ret;

  if (data == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) data,
				     (char *) "xmlSecKeyDataPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecKeyDataId(xmlSecKeyDataId dataId) {
  PyObject *ret;

  if (dataId == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) dataId,
				     (char *) "xmlSecKeyDataId", NULL);
  return (ret);
}

PyObject *wrap_xmlSecKeyDataStorePtr(xmlSecKeyDataStorePtr store) {
  PyObject *ret;

  if (store == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) store,
				     (char *) "xmlSecKeyDataStorePtr", NULL);
  return (ret);
}

/******************************************************************************/

PyObject *xmlsec_KeyDataIdsGet(PyObject *self, PyObject *args) {
  return (wrap_xmlSecPtrListPtr(xmlSecKeyDataIdsGet()));
}

PyObject *xmlsec_KeyDataIdsInit(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecKeyDataIdsInit()));
}

PyObject *xmlsec_KeyDataIdsShutdown(PyObject *self, PyObject *args) {
  xmlSecKeyDataIdsShutdown();

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataIdsRegisterDefault(PyObject *self, PyObject *args) {
  return (wrap_int(xmlSecKeyDataIdsRegisterDefault()));
}

PyObject *xmlsec_KeyDataIdsRegister(PyObject *self, PyObject *args) {
  PyObject *id_obj;
  xmlSecKeyDataId id;

  if (CheckArgs(args, "O:keyDataIdsRegister")) {
    if (!PyArg_ParseTuple(args, "O:keyDataIdsRegister", &id_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecKeyDataId_get(id_obj);

  return (wrap_int(xmlSecKeyDataIdsRegister(id)));
}

/******************************************************************************/
/* KeyData                                                                    */
/******************************************************************************/

PyObject *xmlSecKeyData_getattr(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  const char *attr;

  if (CheckArgs(args, "OS:keyDataGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:keyDataGetAttr", &data_obj, &attr))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[s]", "id");
  if (!strcmp(attr, "id"))
    return (wrap_xmlSecKeyDataId(data->id));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecKeyData_setattr(PyObject *self, PyObject *args) {
  PyObject *data_obj, *value_obj;
  xmlSecKeyDataPtr data;
  const char *name;

  if (CheckArgs(args, "OS?:keyDataSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:keyDataSetAttr",
			  &data_obj, &name, &value_obj))
    return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);
    
  if (!strcmp(name, "id"))
    data->id = xmlSecKeyDataId_get(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_KeyDataCreate(PyObject *self, PyObject *args) {
  PyObject *id_obj;
  xmlSecKeyDataId id;

  if (CheckArgs(args, "O:keyDataCreate")) {
    if (!PyArg_ParseTuple(args, "O:keyDataCreate", &id_obj))
      return NULL;
  }
  else return NULL;

  id  = xmlSecKeyDataId_get(id_obj);

  return (wrap_xmlSecKeyDataPtr(xmlSecKeyDataCreate(id)));
}

PyObject *xmlsec_KeyDataDuplicate(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataDuplicate")) {
    if (!PyArg_ParseTuple(args, "O:keyDataDuplicate", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_xmlSecKeyDataPtr(xmlSecKeyDataDuplicate(data)));
}

PyObject *xmlsec_KeyDataDestroy(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataDestroy")) {
    if (!PyArg_ParseTuple(args, "O:keyDataDestroy", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);
  xmlSecKeyDataDestroy(data);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataGenerate(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  xmlSecSize sizeBits;
  xmlSecKeyDataType type;

  if (CheckArgs(args, "OII:keyDataGenerate")) {
    if (!PyArg_ParseTuple(args, "Oii:keyDataGenerate",
			  &data_obj, &sizeBits, &type))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataGenerate(data, sizeBits, type)));
}

PyObject *xmlsec_KeyDataGetType(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataGetType")) {
    if (!PyArg_ParseTuple(args, "O:keyDataGetType", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataGetType(data)));
}

PyObject *xmlsec_KeyDataGetSize(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataGetSize")) {
    if (!PyArg_ParseTuple(args, "O:keyDataGetSize", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataGetSize(data)));
}

PyObject *xmlsec_KeyDataGetIdentifier(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataGetIdentifier")) {
    if (!PyArg_ParseTuple(args, "O:keyDataGetIdentifier", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_xmlCharPtrConst(xmlSecKeyDataGetIdentifier(data)));
}

PyObject *xmlsec_KeyDataDebugDump(PyObject *self, PyObject *args) {
  PyObject *data_obj, *output_obj;
  xmlSecKeyDataPtr data;
  FILE *output;
  
  if (CheckArgs(args, "O:keyDataDebugDump")) {
    if (!PyArg_ParseTuple(args, "O:keyDataDebugDump", &data_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);
  output = PythonFile_get(output_obj);

  xmlSecKeyDataDebugDump(data, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *data_obj, *output_obj;
  xmlSecKeyDataPtr data;
  FILE *output;
  
  if (CheckArgs(args, "O:keyDataDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "O:keyDataDebugXmlDump", &data_obj,
			  &output_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);
  output = PythonFile_get(output_obj);

  xmlSecKeyDataDebugXmlDump(data, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDataXmlRead(PyObject *self, PyObject *args) {
  PyObject *id_obj, *key_obj, *node_obj, *keyInfoCtx_obj;
  xmlSecKeyDataId id;
  xmlSecKeyPtr key;
  xmlNodePtr node;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOOO:keyDataXmlRead")) {
    if (!PyArg_ParseTuple(args, "OOOO:keyDataXmlRead",
			  &id_obj, &key_obj, &node_obj, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecKeyDataId_get(id_obj);
  key = xmlSecKeyPtr_get(key_obj);
  node = xmlNodePtr_get(node_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyDataXmlRead(id, key, node, keyInfoCtx)));
}

PyObject *xmlsec_KeyDataXmlWrite(PyObject *self, PyObject *args) {
  PyObject *id_obj, *key_obj, *node_obj, *keyInfoCtx_obj;
  xmlSecKeyDataId id;
  xmlSecKeyPtr key;
  xmlNodePtr node;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOOO:keyDataXmlWrite")) {
    if (!PyArg_ParseTuple(args, "OOOO:keyDataXmlWrite",
			  &id_obj, &key_obj, &node_obj, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecKeyDataId_get(id_obj);
  key = xmlSecKeyPtr_get(key_obj);
  node = xmlNodePtr_get(node_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyDataXmlWrite(id, key, node, keyInfoCtx)));
}

PyObject *xmlsec_KeyDataBinRead(PyObject *self, PyObject *args) {
  PyObject *id_obj, *key_obj, *keyInfoCtx_obj;
  xmlSecKeyDataId id;
  xmlSecKeyPtr key;
  const xmlSecByte *buf;
  xmlSecSize bufSize;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOSIO:keyDataBinRead")) {
    if (!PyArg_ParseTuple(args, "OOsiO:keyDataBinRead",
			  &id_obj, &key_obj, &buf, &bufSize, &keyInfoCtx_obj))
      return NULL;
  }
  else return NULL;

  id = xmlSecKeyDataId_get(id_obj);
  key = xmlSecKeyPtr_get(key_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  return (wrap_int(xmlSecKeyDataBinRead(id, key, buf, bufSize, keyInfoCtx)));
}

PyObject *xmlsec_KeyDataBinWrite(PyObject *self, PyObject *args) {
  PyObject *id_obj, *key_obj, *keyInfoCtx_obj;
  xmlSecKeyDataId id;
  xmlSecKeyPtr key;
  // FIXME
  //xmlSecByte **buf;
  //xmlSecSize *bufSize;
  xmlSecByte *buf;
  xmlSecSize bufSize;
  xmlSecKeyInfoCtxPtr keyInfoCtx;

  if (CheckArgs(args, "OOSIO:keyDataBinWrite")) {
    if (!PyArg_ParseTuple(args, "OOsiO:keyDataBinWrite",
			  &id_obj, &key_obj, &buf, &bufSize, &keyInfoCtx_obj))
    return NULL;
  }
  else return NULL;

  id = xmlSecKeyDataId_get(id_obj);
  key = xmlSecKeyPtr_get(key_obj);
  keyInfoCtx = xmlSecKeyInfoCtxPtr_get(keyInfoCtx_obj);

  //return (wrap_int(xmlSecKeyDataBinWrite(id, key, buf, bufSize, keyInfoCtx)));
  return (wrap_int(xmlSecKeyDataBinWrite(id, key, &buf, &bufSize, keyInfoCtx)));
}

PyObject *xmlsec_KeyDataGetName(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataGetName")) {
    if (!PyArg_ParseTuple(args, "O:keyDataGetName", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_xmlCharPtrConst(xmlSecKeyDataGetName(data)));
}

PyObject *xmlsec_KeyDataIsValid(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  
  if (CheckArgs(args, "O:keyDataIsValid")) {
    if (!PyArg_ParseTuple(args, "O:keyDataIsValid", &data_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataIsValid(data)));
}

PyObject *xmlsec_KeyDataCheckId(PyObject *self, PyObject *args) {
  PyObject *data_obj, *dataId_obj;
  xmlSecKeyDataPtr data;
  xmlSecKeyDataId dataId;
  
  if (CheckArgs(args, "OO:keyDataCheckId")) {
    if (!PyArg_ParseTuple(args, "OO:keyDataCheckId", &data_obj, &dataId_obj))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);
  dataId = xmlSecKeyDataId_get(dataId_obj);

  return (wrap_int(xmlSecKeyDataCheckId(data, dataId)));
}

PyObject *xmlsec_KeyDataCheckUsage(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  xmlSecKeyDataUsage usg;
  
  if (CheckArgs(args, "OI:keyDataCheckUsage")) {
    if (!PyArg_ParseTuple(args, "Oi:keyDataCheckUsage", &data_obj, &usg))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataCheckUsage(data, usg)));
}

PyObject *xmlsec_KeyDataCheckSize(PyObject *self, PyObject *args) {
  PyObject *data_obj;
  xmlSecKeyDataPtr data;
  xmlSecSize size;
  
  if (CheckArgs(args, "OI:keyDataCheckSize")) {
    if (!PyArg_ParseTuple(args, "Oi:keyDataCheckSize", &data_obj, &size))
      return NULL;
  }
  else return NULL;

  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyDataCheckSize(data, size)));
}

/******************************************************************************/
/* KeyDataId                                                                  */
/******************************************************************************/

static xmlHashTablePtr KeyDataInitMethods = NULL;
static xmlHashTablePtr KeyDataDuplicateMethods = NULL;
static xmlHashTablePtr KeyDataFinalizeMethods = NULL;
static xmlHashTablePtr KeyDataGenerateMethods = NULL;
static xmlHashTablePtr KeyDataGetTypeMethods = NULL;
static xmlHashTablePtr KeyDataGetSizeMethods = NULL;
static xmlHashTablePtr KeyDataGetIdentifierMethods = NULL;
static xmlHashTablePtr KeyDataXmlReadMethods = NULL;
static xmlHashTablePtr KeyDataXmlWriteMethods = NULL;
static xmlHashTablePtr KeyDataBinReadMethods = NULL;
static xmlHashTablePtr KeyDataBinWriteMethods = NULL;
static xmlHashTablePtr KeyDataDebugDumpMethods = NULL;

static int xmlsec_KeyDataInitMethod(xmlSecKeyDataPtr data) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataInitMethods, data->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyDataPtr(data));

  /* Protect refcount against reentrant manipulation of callback hash */
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_KeyDataDuplicateMethod(xmlSecKeyDataPtr dst,
					 xmlSecKeyDataPtr src) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataDuplicateMethods, src->id->name);

  args = Py_BuildValue((char *) "OO", wrap_xmlSecKeyDataPtr(dst),
		       wrap_xmlSecKeyDataPtr(src));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static void xmlsec_KeyDataFinalizeMethod(xmlSecKeyDataPtr data) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataFinalizeMethods, data->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyDataPtr(data));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

static int xmlsec_KeyDataXmlReadMethod(xmlSecKeyDataId id, xmlSecKeyPtr key,
				       xmlNodePtr node,
				       xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataXmlReadMethods, id->name);

  args = Py_BuildValue((char *) "OOOO", wrap_xmlSecKeyDataId(id),
		       wrap_xmlSecKeyPtr(key), wrap_xmlNodePtr(node),
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_KeyDataXmlWriteMethod(xmlSecKeyDataId id, xmlSecKeyPtr key,
					xmlNodePtr node,
					xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataXmlWriteMethods, id->name);

  args = Py_BuildValue((char *) "OOOO", wrap_xmlSecKeyDataId(id),
		       wrap_xmlSecKeyPtr(key), wrap_xmlNodePtr(node),
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_KeyDataBinReadMethod(xmlSecKeyDataId id,
				      xmlSecKeyPtr key,
				      const xmlSecByte *buf,
				      xmlSecSize bufSize,
				      xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataBinReadMethods, id->name);

  args = Py_BuildValue((char *) "OOsiO", wrap_xmlSecKeyDataId(id),
		       wrap_xmlSecKeyPtr(key), buf, bufSize,
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static int xmlsec_KeyDataBinWriteMethod(xmlSecKeyDataId id,
					xmlSecKeyPtr key,
					const xmlSecByte **buf,
					xmlSecSize *bufSize,
					xmlSecKeyInfoCtxPtr keyInfoCtx) {
  PyObject *args, *result;
  PyObject *func = NULL;
  
  func = xmlHashLookup(KeyDataBinWriteMethods, id->name);
  
  // FIXME : buf, bufSize
  args = Py_BuildValue((char *) "OOsiO", wrap_xmlSecKeyDataId(id),
		       wrap_xmlSecKeyPtr(key), &buf, &bufSize,
		       wrap_xmlSecKeyInfoCtxPtr(keyInfoCtx));
  
  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);
  
  return (PyInt_AsLong(result));
}

static int xmlsec_KeyDataGenerateMethod(xmlSecKeyDataPtr data,
				       xmlSecSize sizeBits,
				       xmlSecKeyDataType type) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataGenerateMethods, data->id->name);

  args = Py_BuildValue((char *) "Oii", wrap_xmlSecKeyDataPtr(data),
		       sizeBits, type);

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static xmlSecKeyDataType xmlsec_KeyDataGetTypeMethod(xmlSecKeyDataPtr data) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataGetTypeMethods, data->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyDataPtr(data));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static xmlSecKeyDataType xmlsec_KeyDataGetSizeMethod(xmlSecKeyDataPtr data) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataGetSizeMethods, data->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyDataPtr(data));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyInt_AsLong(result));
}

static const xmlChar* xmlsec_KeyDataGetIdentifierMethod(xmlSecKeyDataPtr data) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataGetIdentifierMethods, data->id->name);

  args = Py_BuildValue((char *) "O", wrap_xmlSecKeyDataPtr(data));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  return (PyString_AsString(result));
}

static void xmlsec_KeyDataDebugDumpMethod(xmlSecKeyDataPtr data, FILE *output) {
  PyObject *args, *result;
  PyObject *func = NULL;

  func = xmlHashLookup(KeyDataDebugDumpMethods, data->id->name);

  args = Py_BuildValue((char *) "OO", wrap_xmlSecKeyDataPtr(data),
		       PyFile_FromFile(output, NULL, NULL, NULL));

  Py_INCREF(func);
  result = PyEval_CallObject(func, args);
  Py_DECREF(func);
  Py_DECREF(args);

  Py_XDECREF(result);
}

/******************************************************************************/

PyObject *keysdata_KeyDataIdCreate(PyObject *self, PyObject *args) {
  PyObject *initialize_obj, *duplicate_obj, *finalize_obj, *generate_obj;
  PyObject *getType_obj, *getSize_obj, *getIdentifier_obj;
  PyObject *xmlRead_obj, *xmlWrite_obj, *binRead_obj, *binWrite_obj;
  PyObject *debugDump_obj, *debugXmlDump_obj;
  xmlSecSize klassSize;
  xmlSecSize objSize;
  const xmlChar *name;    
  xmlSecKeyDataUsage usage;
  const xmlChar *href;
  const xmlChar *dataNodeName;
  const xmlChar *dataNodeNs;
  /* new KeyDataId */
  struct _xmlSecKeyDataKlass *dataId;

  if (CheckArgs(args, "IISISSSccccccccccccc:keyDataIdCreate")) {
    if (!PyArg_ParseTuple(args, (char *) "iisisssOOOOOOOOOOOOO:keyDataIdCreate",
			  &klassSize, &objSize, &name, &usage,
			  &href, &dataNodeName, &dataNodeNs,
			  &initialize_obj, &duplicate_obj, &finalize_obj,
			  &generate_obj, &getType_obj, &getSize_obj,
			  &getIdentifier_obj, &xmlRead_obj, &xmlWrite_obj,
			  &binRead_obj, &binWrite_obj, &debugDump_obj,
			  &debugXmlDump_obj))
      return NULL;
  }
  else return NULL;
  
  if (KeyDataInitMethods == NULL && initialize_obj != Py_None)
    KeyDataInitMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataDuplicateMethods == NULL && duplicate_obj != Py_None)
    KeyDataDuplicateMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataFinalizeMethods == NULL && finalize_obj != Py_None)
    KeyDataFinalizeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataGenerateMethods == NULL && generate_obj != Py_None)
    KeyDataGenerateMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataGetTypeMethods == NULL && getType_obj != Py_None)
    KeyDataGetTypeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataGetSizeMethods == NULL && getSize_obj != Py_None)
    KeyDataGetSizeMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataGetIdentifierMethods == NULL && getIdentifier_obj != Py_None)
    KeyDataGetIdentifierMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataXmlReadMethods == NULL && xmlRead_obj != Py_None)
    KeyDataXmlReadMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataXmlWriteMethods == NULL && xmlWrite_obj != Py_None)
    KeyDataXmlWriteMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataBinReadMethods == NULL && binRead_obj != Py_None)
    KeyDataBinReadMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataBinWriteMethods == NULL && binWrite_obj != Py_None)
    KeyDataBinWriteMethods = xmlHashCreate(HASH_TABLE_SIZE);
  if (KeyDataDebugDumpMethods == NULL &&
      (debugDump_obj != Py_None || debugXmlDump_obj != Py_None))
    KeyDataDebugDumpMethods = xmlHashCreate(HASH_TABLE_SIZE * 2);

  if (initialize_obj != Py_None)
    xmlHashAddEntry(KeyDataInitMethods, name, initialize_obj);
  if (duplicate_obj != Py_None)
    xmlHashAddEntry(KeyDataDuplicateMethods, name, duplicate_obj);
  if (finalize_obj != Py_None)
    xmlHashAddEntry(KeyDataFinalizeMethods, name, finalize_obj);
  if (generate_obj != Py_None)
    xmlHashAddEntry(KeyDataGenerateMethods, name, generate_obj);
  if (getType_obj != Py_None)
    xmlHashAddEntry(KeyDataGetTypeMethods, name, getType_obj);
  if (getSize_obj != Py_None)
    xmlHashAddEntry(KeyDataGetSizeMethods, name, getSize_obj);
  if (getIdentifier_obj != Py_None)
    xmlHashAddEntry(KeyDataGetIdentifierMethods, name, getIdentifier_obj);
  if (xmlRead_obj != Py_None)
    xmlHashAddEntry(KeyDataXmlReadMethods, name, xmlRead_obj);
  if (xmlWrite_obj != Py_None)
    xmlHashAddEntry(KeyDataXmlWriteMethods, name, xmlWrite_obj);
  if (binRead_obj != Py_None)
    xmlHashAddEntry(KeyDataBinReadMethods, name, binRead_obj);
  if (binWrite_obj != Py_None)
    xmlHashAddEntry(KeyDataBinWriteMethods, name, binWrite_obj);
  if (debugDump_obj != Py_None)
    xmlHashAddEntry(KeyDataDebugDumpMethods, name, debugDump_obj);
  if (debugXmlDump_obj != Py_None)
    xmlHashAddEntry(KeyDataDebugDumpMethods, name, debugXmlDump_obj);

  dataId = xmlMalloc(sizeof(xmlSecKeyDataKlass));

  /* FIXME
    dataId->klassSize = klassSize;
    dataId->objSize = objSize;
  */
  dataId->klassSize = sizeof(xmlSecKeyDataKlass);
  dataId->objSize = sizeof(xmlSecKeyData);
  dataId->name = name;
  dataId->usage = usage;
  dataId->href = href;
  dataId->dataNodeName = dataNodeName;
  dataId->dataNodeNs = dataNodeNs;

  if (initialize_obj != Py_None)
    dataId->initialize = xmlsec_KeyDataInitMethod;
  else
    dataId->initialize = NULL;
  if (duplicate_obj != Py_None)
    dataId->duplicate = xmlsec_KeyDataDuplicateMethod;
  else
    dataId->duplicate = NULL;
  if (finalize_obj != Py_None)
    dataId->finalize = xmlsec_KeyDataFinalizeMethod;
  else
    dataId->finalize = NULL;
  if (generate_obj != Py_None)
    dataId->generate = xmlsec_KeyDataGenerateMethod;
  else
    dataId->generate = NULL;
  if (getType_obj != Py_None)
    dataId->getType = xmlsec_KeyDataGetTypeMethod;
  else
    dataId->getType = NULL;
  if (getSize_obj != Py_None)
    dataId->getSize = xmlsec_KeyDataGetSizeMethod;
  else
    dataId->getSize = NULL;
  if (getIdentifier_obj != Py_None)
    dataId->getIdentifier = xmlsec_KeyDataGetIdentifierMethod;
  else
    dataId->getIdentifier = NULL;
  if (xmlRead_obj != Py_None)
    dataId->xmlRead = xmlsec_KeyDataXmlReadMethod;
  else
    dataId->xmlRead = NULL;
  if (xmlWrite_obj != Py_None)
    dataId->xmlWrite = xmlsec_KeyDataXmlWriteMethod;
  else
    dataId->xmlWrite = NULL;
  if (binRead_obj != Py_None)
    dataId->binRead = xmlsec_KeyDataBinReadMethod;
  else
    dataId->binRead = NULL;
  if (binWrite_obj != Py_None)
    dataId->binWrite = xmlsec_KeyDataBinWriteMethod;
  else
    dataId->binWrite = NULL;
  if (debugDump_obj != Py_None)
    dataId->debugDump = xmlsec_KeyDataDebugDumpMethod;
  else
    dataId->debugDump = NULL;
  if (debugXmlDump_obj != Py_None)
    dataId->debugXmlDump = xmlsec_KeyDataDebugDumpMethod;
  else
    dataId->debugXmlDump = NULL;

  Py_XINCREF(initialize_obj);
  Py_XINCREF(duplicate_obj);
  Py_XINCREF(finalize_obj);
  Py_XINCREF(generate_obj);
  Py_XINCREF(getType_obj);
  Py_XINCREF(getSize_obj);
  Py_XINCREF(getIdentifier_obj);
  Py_XINCREF(xmlRead_obj);
  Py_XINCREF(xmlWrite_obj);
  Py_XINCREF(binRead_obj);
  Py_XINCREF(binWrite_obj);
  Py_XINCREF(debugDump_obj);
  Py_XINCREF(debugXmlDump_obj);

  return (wrap_xmlSecKeyDataId(dataId));
}

PyObject *xmlsec_KeyDataKlassGetName(PyObject *self, PyObject *args) {
  PyObject *dataId_obj;
  xmlSecKeyDataId dataId;
  
  if (CheckArgs(args, "O:keyDataIdGetName")) {
    if (!PyArg_ParseTuple(args, "O:keyDataIdGetName", &dataId_obj))
      return NULL;
  }
  else return NULL;

  dataId = xmlSecKeyDataId_get(dataId_obj);

  return (wrap_xmlCharPtrConst(xmlSecKeyDataKlassGetName(dataId)));
}
