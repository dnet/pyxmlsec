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

#include "keys.h"
#include "buffer.h"
#include "keysdata.h"
#include "list.h"

PyObject *wrap_xmlSecKeyReqPtr(xmlSecKeyReqPtr keyReq) {
  PyObject *ret;

  if (keyReq == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) keyReq,
				     (char *) "xmlSecKeyReqPtr", NULL);
  return (ret);
}

PyObject *wrap_xmlSecKeyPtr(xmlSecKeyPtr key) {
  PyObject *ret;

  if (key == NULL) {
    Py_INCREF(Py_None);
    return (Py_None);
  }
  ret = PyCObject_FromVoidPtrAndDesc((void *) key,
				     (char *) "xmlSecKeyPtr", NULL);
  return (ret);
}

/******************************************************************************/
/* KeyReq                                                                     */
/******************************************************************************/

PyObject *xmlSecKeyReq_getattr(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj;
  xmlSecKeyReqPtr keyReq;
  const char *attr;

  if (CheckArgs(args, "OS:keyReqGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:keyReqGetAttr", &keyReq_obj, &attr))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssss]", "keyId", "keyType",
			 "keyUsage", "keyBitsSize");
  if (!strcmp(attr, "keyId"))
    return wrap_xmlSecKeyDataId(keyReq->keyId);
  if (!strcmp(attr, "keyType"))
    return wrap_int(keyReq->keyType);
  if (!strcmp(attr, "keyUsage"))
    return wrap_int(keyReq->keyUsage);
  if (!strcmp(attr, "keyBitsSize"))
    return wrap_int(keyReq->keyBitsSize);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecKeyReq_setattr(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj, *value_obj;
  xmlSecKeyReqPtr keyReq;
  const char *name;

  if (CheckArgs(args, "OS?:keyReqSetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:keyReqSetAttr",
			  &keyReq_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);

  if (!strcmp(name, "keyId"))
    keyReq->keyId = xmlSecKeyDataId_get(value_obj);
  else if (!strcmp(name, "keyType"))
    keyReq->keyType = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keyUsage"))
    keyReq->keyUsage = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "keyBitsSize"))
    keyReq->keyBitsSize = PyInt_AsLong(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *keys_KeyReqCreate(PyObject *self, PyObject *args) {
  PyObject *keyId_obj;
  xmlSecKeyDataType keyType;
  xmlSecKeyUsage keyUsage;
  xmlSecSize keyBitsSize;
  xmlSecKeyReqPtr keyReq;

  if (CheckArgs(args, "OIII:keyReqCreate")) {
    if (!PyArg_ParseTuple(args, "Oiii:keyReqCreate", &keyId_obj, &keyType,
			  &keyUsage, &keyBitsSize))
      return NULL;
  }
  else return NULL;

  keyReq = (xmlSecKeyReqPtr) xmlMalloc(sizeof(xmlSecKeyReq));
  keyReq->keyId       = xmlSecKeyDataId_get(keyId_obj);
  keyReq->keyType     = keyType;
  keyReq->keyUsage    = keyUsage;
  keyReq->keyBitsSize = keyBitsSize;
  
  return (wrap_xmlSecKeyReqPtr(keyReq));
}

PyObject *xmlsec_KeyReqInitialize(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj;
  xmlSecKeyReqPtr keyReq;

  if (CheckArgs(args, "O:keyReqInitialize")) {
    if (!PyArg_ParseTuple(args, "O:keyReqInitialize", &keyReq_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);

  return (wrap_int(xmlSecKeyReqInitialize(keyReq)));
}

PyObject *xmlsec_KeyReqFinalize(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj;
  xmlSecKeyReqPtr keyReq;

  if (CheckArgs(args, "O:keyReqFinalize")) {
    if (!PyArg_ParseTuple(args, "O:keyReqFinalize", &keyReq_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  xmlSecKeyReqFinalize(keyReq);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyReqReset(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj;
  xmlSecKeyReqPtr keyReq;

  if (CheckArgs(args, "O:keyReqReset")) {
    if (!PyArg_ParseTuple(args, "O:keyReqReset", &keyReq_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  xmlSecKeyReqReset(keyReq);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyReqCopy(PyObject *self, PyObject *args) {
  PyObject *dst_obj, *src_obj;
  xmlSecKeyReqPtr dst;
  xmlSecKeyReqPtr src;

  if (CheckArgs(args, "OO:keyReqCopy")) {
    if (!PyArg_ParseTuple(args, "OO:keyReqCopy", &dst_obj, &src_obj))
      return NULL;
  }
  else return NULL;

  dst = xmlSecKeyReqPtr_get(dst_obj);
  src = xmlSecKeyReqPtr_get(src_obj);
  
  return (wrap_int(xmlSecKeyReqCopy(dst, src)));
}

PyObject *xmlsec_KeyReqMatchKey(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj, *key_obj;
  xmlSecKeyReqPtr keyReq;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:keyReqMatchKey")) {
    if (!PyArg_ParseTuple(args, "OO:keyReqMatchKey", &keyReq_obj, &key_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_int(xmlSecKeyReqMatchKey(keyReq, key)));
}

PyObject *xmlsec_KeyReqMatchKeyValue(PyObject *self, PyObject *args) {
  PyObject *keyReq_obj, *value_obj;
  xmlSecKeyReqPtr keyReq;
  xmlSecKeyDataPtr value;

  if (CheckArgs(args, "OO:keyReqMatchKeyValue")) {
    if (!PyArg_ParseTuple(args, "OO:keyReqMatchKeyValue",
			  &keyReq_obj, &value_obj))
      return NULL;
  }
  else return NULL;

  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);
  value = xmlSecKeyDataPtr_get(value_obj);

  return (wrap_int(xmlSecKeyReqMatchKeyValue(keyReq, value)));
}

/******************************************************************************/
/* Key                                                                        */
/******************************************************************************/

PyObject *xmlSecKey_getattr(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;
  const char *attr;

  if (CheckArgs(args, "OS:keyGetAttr")) {
    if (!PyArg_ParseTuple(args, "Os:keyGetAttr", &key_obj, &attr))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  if (!strcmp(attr, "__members__"))
    return Py_BuildValue("[ssssss]", "name", "value", "dataList", "usage",
			 "notValidBefore", "notValidAfter");
  if (!strcmp(attr, "name"))
    return (wrap_xmlCharPtr(key->name));
  if (!strcmp(attr, "value"))
    return (wrap_xmlSecKeyDataPtr(key->value));
  if (!strcmp(attr, "dataList"))
    return (wrap_xmlSecPtrListPtr(key->dataList));
  if (!strcmp(attr, "usage"))
    return (wrap_int(key->usage));
  if (!strcmp(attr, "notValidBefore"))
    return (wrap_int(key->notValidBefore));
  if (!strcmp(attr, "notValidAfter"))
    return (wrap_int(key->notValidAfter));

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlSecKey_setattr(PyObject *self, PyObject *args) {
  PyObject *key_obj, *value_obj;
  xmlSecKeyPtr key;
  const char *name;

  if (CheckArgs(args, "OS?:keySetAttr")) {
    if (!PyArg_ParseTuple(args, "OsO:keySetAttr",
			  &key_obj, &name, &value_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);
    
  if (!strcmp(name, "name"))
    key->name = PyString_AsString(value_obj);
  else if (!strcmp(name, "value"))
    key->value = xmlSecKeyDataPtr_get(value_obj);
  else if (!strcmp(name, "dataList"))
    key->dataList = xmlSecPtrListPtr_get(value_obj);
  else if (!strcmp(name, "usage"))
    key->usage = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "notValidBefore"))
    key->notValidBefore = PyInt_AsLong(value_obj);
  else if (!strcmp(name, "notValidAfter"))
    key->notValidAfter = PyInt_AsLong(value_obj);

  Py_INCREF(Py_None);
  return (Py_None);
}

/******************************************************************************/

PyObject *xmlsec_KeyCreate(PyObject *self, PyObject *args) {
  return (wrap_xmlSecKeyPtr(xmlSecKeyCreate()));
}

PyObject *xmlsec_KeyDestroy(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyDestroy")) {
    if (!PyArg_ParseTuple(args, "O:keyDestroy", &key_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  xmlSecKeyDestroy(key);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyEmpty(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyEmpty")) {
    if (!PyArg_ParseTuple(args, "O:keyEmpty", &key_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  xmlSecKeyEmpty(key);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDuplicate(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyDuplicate")) {
    if (!PyArg_ParseTuple(args, "O:keyDuplicate", &key_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_xmlSecKeyPtr(xmlSecKeyDuplicate(key)));
}

PyObject *xmlsec_KeyCopy(PyObject *self, PyObject *args) {
  PyObject *keyDst_obj, *keySrc_obj;
  xmlSecKeyPtr keyDst;
  xmlSecKeyPtr keySrc;

  if (CheckArgs(args, "OO:keyCopy")) {
    if (!PyArg_ParseTuple(args, "OO:keyCopy", &keyDst_obj, &keySrc_obj))
      return NULL;
  }
  else return NULL;

  keyDst = xmlSecKeyPtr_get(keyDst_obj);
  keySrc = xmlSecKeyPtr_get(keySrc_obj);

  return (wrap_int(xmlSecKeyCopy(keyDst, keySrc)));
}

PyObject *xmlsec_KeyGetName(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyGetName")) {
    if (!PyArg_ParseTuple(args, "O:keyGetName", &key_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_xmlCharPtrConst(xmlSecKeyGetName(key)));
}

PyObject *xmlsec_KeySetName(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;
  const xmlChar *name;
  
  if (CheckArgs(args, "OS:keySetName")) {
    if (!PyArg_ParseTuple(args, "Os:keySetName", &key_obj, &name))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_int(xmlSecKeySetName(key, name)));
}

PyObject *xmlsec_KeyGetType(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataType type;

  if (CheckArgs(args, "O:keyGetType")) {
    if (!PyArg_ParseTuple(args, "O:keyGetType", &key_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  type = xmlSecKeyGetType(key);

  return (wrap_int(type));
}

PyObject *xmlsec_KeyGetValue(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataPtr value;

  if (CheckArgs(args, "O:keyGetValue")) {
    if (!PyArg_ParseTuple(args, "O:keyGetValue", &key_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  value = xmlSecKeyGetValue(key);

  return (wrap_xmlSecKeyDataPtr(value));
}

PyObject *xmlsec_KeySetValue(PyObject *self, PyObject *args) {
  PyObject *key_obj, *value_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataPtr value;

  if (CheckArgs(args, "OO:keySetValue")) {
    if (!PyArg_ParseTuple(args, "OO:keySetValue", &key_obj, &value_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  value = xmlSecKeyDataPtr_get(value_obj);

  return (wrap_int(xmlSecKeySetValue(key, value)));
}

PyObject *xmlsec_KeyGetData(PyObject *self, PyObject *args) {
  PyObject *key_obj, *dataId_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataId dataId;
  xmlSecKeyDataPtr data;

  if (CheckArgs(args, "OO:keyGetData")) {
    if (!PyArg_ParseTuple(args, "OO:keyGetData", &key_obj, &dataId_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  dataId = xmlSecKeyDataId_get(dataId_obj);
  data = xmlSecKeyGetData(key, dataId);

  return (wrap_xmlSecKeyDataPtr(data));
}

PyObject *xmlsec_KeyEnsureData(PyObject *self, PyObject *args) {
  PyObject *key_obj, *dataId_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataId dataId;
  xmlSecKeyDataPtr data;

  if (CheckArgs(args, "OO:keyEnsureData")) {
    if (!PyArg_ParseTuple(args, "OO:keyEnsureData", &key_obj, &dataId_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  dataId = xmlSecKeyDataId_get(dataId_obj);
  data = xmlSecKeyEnsureData(key, dataId);

  return (wrap_xmlSecKeyDataPtr(data));
}

PyObject *xmlsec_KeyAdoptData(PyObject *self, PyObject *args) {
  PyObject *key_obj, *data_obj;
  xmlSecKeyPtr key;
  xmlSecKeyDataPtr data;

  if (CheckArgs(args, "OO:keyAdoptData")) {
    if (!PyArg_ParseTuple(args, "OO:keyAdoptData", &key_obj, &data_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
  data = xmlSecKeyDataPtr_get(data_obj);

  return (wrap_int(xmlSecKeyAdoptData(key, data)));
}

PyObject *xmlsec_KeyDebugDump(PyObject *self, PyObject *args) {
  PyObject *key_obj, *output_obj;
  FILE *output;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:keyDebugDump")) {
    if (!PyArg_ParseTuple(args, "OO:keyDebugDump", &key_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);
  output = PythonFile_get(output_obj);
  xmlSecKeyDebugDump(key, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyDebugXmlDump(PyObject *self, PyObject *args) {
  PyObject *key_obj, *output_obj;
  FILE *output;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:keyDebugXmlDump")) {
    if (!PyArg_ParseTuple(args, "OO:keyDebugXmlDump", &key_obj, &output_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);
  output = PythonFile_get(output_obj);
  xmlSecKeyDebugXmlDump(key, output);

  Py_INCREF(Py_None);
  return (Py_None);
}

PyObject *xmlsec_KeyGenerate(PyObject *self, PyObject *args) {
  PyObject *dataId_obj;
  xmlSecKeyDataId dataId;
  xmlSecSize sizeBits;
  xmlSecKeyDataType type;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OII:keyGenerate")) {
    if (!PyArg_ParseTuple(args, "Oii:keyGenerate",
			  &dataId_obj, &sizeBits, &type))
      return NULL;
  }
  else return NULL;

  dataId = xmlSecKeyDataId_get(dataId_obj);
  key = xmlSecKeyGenerate(dataId, sizeBits, type);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeyGenerateByName(PyObject *self, PyObject *args) {
  const xmlChar *name;
  xmlSecSize sizeBits;
  xmlSecKeyDataType type;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OII:keyGenerateByName")) {
    if (!PyArg_ParseTuple(args, "sii:keyGenerateByName", &name, &sizeBits,
			  &type))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyGenerateByName(name, sizeBits, type);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeyMatch(PyObject *self, PyObject *args) {
  PyObject *key_obj, *keyReq_obj;
  xmlSecKeyPtr key;
  const xmlChar *name = NULL;
  xmlSecKeyReqPtr keyReq;

  if (CheckArgs(args, "OsO:keyMatch")) {
    if (!PyArg_ParseTuple(args, "OzO:keyMatch", &key_obj, &name, &keyReq_obj))
      return NULL;
  }
  else return NULL;

  key = xmlSecKeyPtr_get(key_obj);
  keyReq = xmlSecKeyReqPtr_get(keyReq_obj);

  return (wrap_int(xmlSecKeyMatch(key, name, keyReq)));
}

PyObject *xmlsec_KeyReadBuffer(PyObject *self, PyObject *args) {
  PyObject *dataId_obj, *buffer_obj;
  xmlSecKeyDataId dataId;
  xmlSecBuffer *buffer;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OO:keyReadBuffer")) {
    if (!PyArg_ParseTuple(args, "OO:keyReadBuffer", &dataId_obj, &buffer_obj))
      return NULL;
  }
  else return NULL;

  dataId = xmlSecKeyDataId_get(dataId_obj);
  buffer = xmlSecBufferPtr_get(buffer_obj);
  key = xmlSecKeyReadBuffer(dataId, buffer);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeyReadBinaryFile(PyObject *self, PyObject *args) {
  PyObject *dataId_obj;
  xmlSecKeyDataId dataId;
  const char *filename;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OS:keyReadBinaryFile")) {
    if (!PyArg_ParseTuple(args, "Os:keyReadBinaryFile", &dataId_obj, &filename))
      return NULL;
  }
  else return NULL;

  dataId = xmlSecKeyDataId_get(dataId_obj);
  key = xmlSecKeyReadBinaryFile(dataId, filename);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeyReadMemory(PyObject *self, PyObject *args) {
  PyObject *dataId_obj;
  xmlSecKeyDataId dataId;
  const xmlSecByte *data;
  xmlSecSize dataSize;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "OSI:keyReadMemory")) {
    if (!PyArg_ParseTuple(args, "Osi:keyReadMemory", &dataId_obj, &data,
			  &dataSize))
      return NULL;
  }
  else return NULL;

  dataId = xmlSecKeyDataId_get(dataId_obj);
  key = xmlSecKeyReadMemory(dataId, data, dataSize);

  return (wrap_xmlSecKeyPtr(key));
}

PyObject *xmlsec_KeyIsValid(PyObject *self, PyObject *args) {
  PyObject *key_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyIsValid")) {
    if (!PyArg_ParseTuple(args, "O:keyIsValid", &key_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);

  return (wrap_int(xmlSecKeyIsValid(key)));
}

PyObject *xmlsec_KeyCheckId(PyObject *self, PyObject *args) {
  PyObject *key_obj, *keyId_obj;
  xmlSecKeyPtr key;

  if (CheckArgs(args, "O:keyCheckId")) {
    if (!PyArg_ParseTuple(args, "O:keyCheckId", &key_obj, &keyId_obj))
      return NULL;
  }
  else return NULL;
  
  key = xmlSecKeyPtr_get(key_obj);
 
  return (wrap_int(xmlSecKeyCheckId(key, xmlSecKeyDataId_get(keyId_obj))));
}

PyObject *xmlsec_KeyPtrListId(PyObject *self, PyObject *args) {
  return (wrap_xmlSecPtrListId(xmlSecKeyPtrListId));
}
