/* $Id$ 
 *
 * pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Easter-eggs, Valery Febvre
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
#include "base64.h"
#include "xmlenc.h"
#include "xmlsec.h"
#include "xmltree.h"
#include "xmldsig.h"
#include "templates.h"
#include "transforms.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysmngr.h"
#include "list.h"
#include "app.h"
#include "buffer.h"
#include "membuf.h"
#include "x509.h"
#include "parser.h"
#include "openssl.h"

static PyMethodDef xmlsec_methods[] = {
  /* xmlsec.h */
  {"init",              xmlsec_Init,              METH_VARARGS},
  {"shutdown",          xmlsec_Shutdown,          METH_VARARGS},
  {"checkVersionExact", xmlsec_CheckVersionExact, METH_VARARGS},
  {"checkVersion",      xmlsec_CheckVersion,      METH_VARARGS},

  /* base64.h */
  {"base64CtxCreate",     xmlsec_Base64CtxCreate,     METH_VARARGS},
  {"base64CtxDestroy",    xmlsec_Base64CtxDestroy,    METH_VARARGS},
  {"base64CtxInitialize", xmlsec_Base64CtxInitialize, METH_VARARGS},
  {"base64CtxFinalize",   xmlsec_Base64CtxFinalize,   METH_VARARGS},
  {"base64CtxUpdate",     xmlsec_Base64CtxUpdate,     METH_VARARGS},
  {"base64CtxFinal",      xmlsec_Base64CtxFinal,      METH_VARARGS},
  {"base64Encode",        xmlsec_Base64Encode,        METH_VARARGS},
  {"base64Decode",        xmlsec_Base64Decode,        METH_VARARGS},

  /* parser.h */
  {"parseFile",            xmlsec_ParseFile,            METH_VARARGS},
  {"parseMemory",          xmlsec_ParseMemory,          METH_VARARGS},
  {"parseMemoryExt",       xmlsec_ParseMemoryExt,       METH_VARARGS},
  {"transformXmlParserId", xmlsec_TransformXmlParserId, METH_VARARGS},

  /* xmlenc.h */
  {"encCtxCreate",          xmlsec_EncCtxCreate,          METH_VARARGS},
  {"encCtxDestroy",         xmlsec_EncCtxDestroy,         METH_VARARGS},
  {"encCtxInitialize",      xmlsec_EncCtxInitialize,      METH_VARARGS},
  {"encCtxFinalize",        xmlsec_EncCtxFinalize,        METH_VARARGS},
  {"encCtxCopyUserPref",    xmlsec_EncCtxCopyUserPref,    METH_VARARGS},
  {"encCtxReset",           xmlsec_EncCtxReset,           METH_VARARGS},
  {"encCtxBinaryEncrypt",   xmlsec_EncCtxBinaryEncrypt,   METH_VARARGS},
  {"encCtxXmlEncrypt",      xmlsec_EncCtxXmlEncrypt,      METH_VARARGS},
  {"encCtxUriEncrypt",      xmlsec_EncCtxUriEncrypt,      METH_VARARGS},
  {"encCtxDecrypt",         xmlsec_EncCtxDecrypt,         METH_VARARGS},
  {"encCtxDecryptToBuffer", xmlsec_EncCtxDecryptToBuffer, METH_VARARGS},
  {"encCtxDebugDump",       xmlsec_EncCtxDebugDump,       METH_VARARGS},
  {"encCtxDebugXmlDump",    xmlsec_EncCtxDebugXmlDump,    METH_VARARGS},
  {"encCtxSetEncKey",       xmlenc_set_encKey,            METH_VARARGS}, // New

  /* xmltree.h */
  {"nodeGetName",        xmlsec_NodeGetName,        METH_VARARGS},
  {"getNodeNsHref",      xmlsec_GetNodeNsHref,      METH_VARARGS},
  {"checkNodeName",      xmlsec_CheckNodeName,      METH_VARARGS},
  {"getNextElementNode", xmlsec_GetNextElementNode, METH_VARARGS},
  {"findChild",          xmlsec_FindNode,           METH_VARARGS},
  {"findParent",         xmlsec_FindNode,           METH_VARARGS},
  {"findNode",           xmlsec_FindNode,           METH_VARARGS},
  {"addChild",           xmlsec_AddChild,           METH_VARARGS},
  {"addNextSibling",     xmlsec_AddNextSibling,     METH_VARARGS},
  {"addPrevSibling",     xmlsec_AddPrevSibling,     METH_VARARGS},
  {"replaceNode",        xmlsec_ReplaceNode,        METH_VARARGS},
  {"replaceContent",     xmlsec_ReplaceContent,     METH_VARARGS},
  {"replaceNodeBuffer",  xmlsec_ReplaceNodeBuffer,  METH_VARARGS},
  {"addIDs",             xmlsec_AddIDs,             METH_VARARGS},
  {"createTree",         xmlsec_CreateTree,         METH_VARARGS},
  {"isEmptyNode",        xmlsec_IsEmptyNode,        METH_VARARGS},
  {"isEmptyString",      xmlsec_IsEmptyString,      METH_VARARGS},
  {"isHex",              xmlsec_IsHex,              METH_VARARGS},
  {"getHex",             xmlsec_GetHex,             METH_VARARGS},

  /* xmldsig.h */
  {"dsigCtxCreate",                      xmlsec_DSigCtxCreate,                      METH_VARARGS},
  {"dsigCtxDestroy",                     xmlsec_DSigCtxDestroy,                     METH_VARARGS},
  {"dsigCtxInitialize",                  xmlsec_DSigCtxInitialize,                  METH_VARARGS},
  {"dsigCtxFinalize",                    xmlsec_DSigCtxFinalize,                    METH_VARARGS},
  {"dsigCtxSign",                        xmlsec_DSigCtxSign,                        METH_VARARGS},
  {"dsigCtxVerify",                      xmlsec_DSigCtxVerify,                      METH_VARARGS},
  {"dsigCtxEnableReferenceTransform",    xmlsec_DSigCtxEnableReferenceTransform,    METH_VARARGS},
  {"dsigCtxEnableSignatureTransform",    xmlsec_DSigCtxEnableSignatureTransform,    METH_VARARGS},
  {"dsigCtxGetPreSignBuffer",            xmlsec_DSigCtxGetPreSignBuffer,            METH_VARARGS},
  {"dsigCtxDebugDump",                   xmlsec_DSigCtxDebugDump,                   METH_VARARGS},
  {"dsigCtxDebugXmlDump",                xmlsec_DSigCtxDebugXmlDump,                METH_VARARGS},
  {"dsigReferenceCtxCreate",             xmlsec_DSigReferenceCtxCreate,             METH_VARARGS},
  {"dsigReferenceCtxDestroy",            xmlsec_DSigReferenceCtxDestroy,            METH_VARARGS},
  {"dsigReferenceCtxInitialize",         xmlsec_DSigReferenceCtxInitialize,         METH_VARARGS},
  {"dsigReferenceCtxFinalize",           xmlsec_DSigReferenceCtxFinalize,           METH_VARARGS},
  {"dsigReferenceCtxProcessNode",        xmlsec_DSigReferenceCtxProcessNode,        METH_VARARGS},
  {"dsigReferenceCtxGetPreDigestBuffer", xmlsec_DSigReferenceCtxGetPreDigestBuffer, METH_VARARGS},
  {"dsigReferenceCtxDebugDump",          xmlsec_DSigReferenceCtxDebugDump,          METH_VARARGS},
  {"dsigReferenceCtxDebugXmlDump",       xmlsec_DSigReferenceCtxDebugXmlDump,       METH_VARARGS},
  {"dsigReferenceCtxListId",             xmlsec_DSigReferenceCtxListId,             METH_VARARGS},
  {"dsigCtxSetSignKey",                  xmldsig_set_signKey,                       METH_VARARGS},
  {"dsigCtxSetEnabledReferenceUris",     xmldsig_set_enabledReferenceUris,          METH_VARARGS},
  {"dsigCtxGetStatus",                   xmldsig_get_status,                        METH_VARARGS},
  {"dsigCtxGetKeyInfoReadCtx",           xmldsig_get_keyInfoReadCtx,                METH_VARARGS},
  {"dsigCtxGetSignedInfoReferences",     xmldsig_get_signedInfoReferences,          METH_VARARGS},

  /* app.h */
  {"cryptoInit",         xmlsec_CryptoInit,         METH_VARARGS},
  {"cryptoShutdown",     xmlsec_CryptoShutdown,     METH_VARARGS},
  {"cryptoKeysMngrInit", xmlsec_CryptoKeysMngrInit, METH_VARARGS},
  {"cryptoAppInit",                    xmlsec_CryptoAppInit,                    METH_VARARGS},
  {"cryptoAppShutdown",                xmlsec_CryptoAppShutdown,                METH_VARARGS},
  {"cryptoAppDefaultKeysMngrInit",     xmlsec_CryptoAppDefaultKeysMngrInit,     METH_VARARGS},
  {"cryptoAppDefaultKeysMngrAdoptKey", xmlsec_CryptoAppDefaultKeysMngrAdoptKey, METH_VARARGS},
  {"cryptoAppDefaultKeysMngrLoad",     xmlsec_CryptoAppDefaultKeysMngrLoad,     METH_VARARGS},
  {"cryptoAppDefaultKeysMngrSave",     xmlsec_CryptoAppDefaultKeysMngrSave,     METH_VARARGS},
  {"cryptoAppKeysMngrCertLoad",        xmlsec_CryptoAppKeysMngrCertLoad,        METH_VARARGS},
  {"cryptoAppKeyLoad",                 xmlsec_CryptoAppKeyLoad,                 METH_VARARGS},
  {"transformDsaSha1Id", xmlsec_TransformDsaSha1Id, METH_VARARGS},
  {"transformRsaSha1Id", xmlsec_TransformRsaSha1Id, METH_VARARGS},
  {"transformSha1Id",    xmlsec_TransformSha1Id,    METH_VARARGS},
  {"keyDataDesId",  xmlsec_KeyDataDesId,  METH_VARARGS}, // New
  {"keyDataDsaId",  xmlsec_KeyDataDsaId,  METH_VARARGS},
  {"keyDataRsaId",  xmlsec_KeyDataRsaId,  METH_VARARGS},
  {"keyDataX509Id", xmlsec_KeyDataX509Id, METH_VARARGS},

  /* buffer.h */
  {"bufferCreate",     xmlsec_BufferCreate,     METH_VARARGS},
  {"bufferDestroy",    xmlsec_BufferDestroy,    METH_VARARGS},
  {"bufferInitialize", xmlsec_BufferInitialize, METH_VARARGS},
  {"bufferFinalize",   xmlsec_BufferFinalize,   METH_VARARGS},

  /* membuf.h */
  {"transformMemBufId",        xmlsec_TransformMemBufId,        METH_VARARGS},
  {"transformMemBufGetBuffer", xmlsec_TransformMemBufGetBuffer, METH_VARARGS},

  /* list.h  */
  {"ptrListCreate",  xmlsec_PtrListCreate,  METH_VARARGS},
  {"ptrListDestroy", xmlsec_PtrListDestroy, METH_VARARGS},
  {"ptrListAdd",     xmlsec_PtrListAdd,     METH_VARARGS},
  {"ptrListGetSize", xmlsec_PtrListGetSize, METH_VARARGS},

  /* templates.h */
  {"tmplSignatureCreate",            xmlsec_TmplSignatureCreate,            METH_VARARGS},
  {"tmplSignatureEnsureKeyInfo",     xmlsec_TmplSignatureEnsureKeyInfo,     METH_VARARGS},
  {"tmplSignatureAddReference",      xmlsec_TmplSignatureAddReference,      METH_VARARGS},
  {"tmplSignatureAddObject",         xmlsec_TmplSignatureAddObject,         METH_VARARGS},
  {"tmplSignatureGetSignMethodNode", xmlsec_TmplSignatureGetSignMethodNode, METH_VARARGS},
  {"tmplSignatureGetC14NMethodNode", xmlsec_TmplSignatureGetC14NMethodNode, METH_VARARGS},
  {"tmplReferenceAddTransform",      xmlsec_TmplReferenceAddTransform,      METH_VARARGS},
  {"tmplObjectAddSignProperties",    xmlsec_TmplObjectAddSignProperties,    METH_VARARGS},
  {"tmplObjectAddManifest",          xmlsec_TmplObjectAddManifest,          METH_VARARGS},
  {"tmplManifestAddReference",       xmlsec_TmplManifestAddReference,       METH_VARARGS},
  {"tmplKeyInfoAddKeyName",          xmlsec_TmplKeyInfoAddKeyName,          METH_VARARGS},
  {"tmplKeyInfoAddKeyValue",         xmlsec_TmplKeyInfoAddKeyValue,         METH_VARARGS},
  {"tmplKeyInfoAddX509Data",         xmlsec_TmplKeyInfoAddX509Data,         METH_VARARGS},

  /* transforms.h */
  {"transformInclC14NId",  xmlsec_TransformInclC14NId,  METH_VARARGS},
  {"transformExclC14NId",  xmlsec_TransformExclC14NId,  METH_VARARGS},
  {"transformEnvelopedId", xmlsec_TransformEnvelopedId, METH_VARARGS},

  /* keys.h */
  {"keyReqCreate",      keys_KeyReqCreate,        METH_VARARGS},
  {"keyReqInitialize",  xmlsec_KeyReqInitialize,  METH_VARARGS},
  {"keyReqFinalize",    xmlsec_KeyReqFinalize,    METH_VARARGS},
  {"keyReqReset",       xmlsec_KeyReqReset,       METH_VARARGS},
  {"keyReqMatchKey",    xmlsec_KeyReqMatchKey,    METH_VARARGS},
  {"keyCreate",         xmlsec_KeyCreate,         METH_VARARGS},
  {"keyDestroy",        xmlsec_KeyDestroy,        METH_VARARGS},
  {"keyGetName",        xmlsec_KeySetName,        METH_VARARGS},
  {"keySetName",        xmlsec_KeySetName,        METH_VARARGS},
  {"keyReadBuffer",     xmlsec_KeyReadBuffer,     METH_VARARGS}, // New
  {"keyReadBinaryFile", xmlsec_KeyReadBinaryFile, METH_VARARGS}, // New
  {"keyReadMemory",     xmlsec_KeyReadMemory,     METH_VARARGS}, // New
  /* keyinfo.h */
  {"keyInfoCtxCreate",     xmlsec_KeyInfoCtxCreate,     METH_VARARGS},
  {"keyInfoCtxDestroy",    xmlsec_KeyInfoCtxDestroy,    METH_VARARGS},
  {"keyInfoCtxInitialize", xmlsec_KeyInfoCtxInitialize, METH_VARARGS},
  {"keyInfoCtxFinalize",   xmlsec_KeyInfoCtxFinalize,   METH_VARARGS},
  {"keyInfoCtxReset",      xmlsec_KeyInfoCtxReset,      METH_VARARGS},
  {"getEnabledKeyData",    keyinfo_get_enabledKeyData,  METH_VARARGS},
  /* keysmngr.h */
  {"keysMngrCreate",    xmlsec_KeysMngrCreate,    METH_VARARGS},
  {"keysMngrDestroy",   xmlsec_KeysMngrDestroy,   METH_VARARGS},
  {"keysMngrFindKey",   xmlsec_KeysMngrFindKey,   METH_VARARGS},
  {"keyStoreCreate",    xmlsec_KeyStoreCreate,    METH_VARARGS},
  {"keyStoreDestroy",   xmlsec_KeyStoreDestroy,   METH_VARARGS},
  {"keyStoreFindKey",   xmlsec_KeyStoreFindKey,   METH_VARARGS},
  {"simpleKeysStoreId", xmlsec_SimpleKeysStoreId, METH_VARARGS},

  /* openssl/crypto.h, openssl/app.h */
  {"openSSLAppInit", xmlsec_OpenSSLAppInit, METH_VARARGS},
  {"openSSLInit",    xmlsec_OpenSSLInit,    METH_VARARGS},

  /* x509.h */
  {"x509DataGetNodeContent", xmlsec_X509DataGetNodeContent, METH_VARARGS},

  {NULL, NULL} /* End of Methods Sentinel */
};

void initxmlsecmod(void) {
  PyObject *m, *d;
  
  m = Py_InitModule("xmlsecmod", xmlsec_methods);
  d = PyModule_GetDict(m);

  xmlsec_error = PyErr_NewException("xmlsec.error", NULL, NULL);
  PyDict_SetItemString(d, "error", xmlsec_error);
  Py_INCREF(xmlsec_error);
  PyModule_AddObject(m, "error", xmlsec_error);
}
