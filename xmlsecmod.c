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

#include "xmlsecmod.h"
#include "xmlsec.h"
#include "xmltree.h"
#include "xmldsig.h"
#include "templates.h"
#include "transforms.h"
#include "keyinfo.h"
#include "keys.h"
#include "keysmngr.h"
#include "list.h"
#include "crypto.h"
#include "openssl.h"

static PyMethodDef xmlsec_methods[] = {
  /* xmlsec.h */
  {"init",     xmlsec_Init,     METH_VARARGS},
  {"shutdown", xmlsec_Shutdown, METH_VARARGS},

  /* xmltree.h */
  {"findNode", xmlsec_FindNode, METH_VARARGS},

  /* xmldsig.h */
  {"dsigCtxCreate",                   xmlsec_DSigCtxCreate,                   METH_VARARGS},
  {"dsigCtxDestroy",                  xmlsec_DSigCtxDestroy,                  METH_VARARGS},
  {"dsigCtxSign",                     xmlsec_DSigCtxSign,                     METH_VARARGS},
  {"dsigCtxVerify",                   xmlsec_DSigCtxVerify,                   METH_VARARGS},
  {"dsigCtxEnableReferenceTransform", xmlsec_DSigCtxEnableReferenceTransform, METH_VARARGS},
  {"dsigCtxEnableSignatureTransform", xmlsec_DSigCtxEnableSignatureTransform, METH_VARARGS},
  {"dsigCtxSetSignKey",               xmldsig_set_signKey,                    METH_VARARGS},
  {"dsigCtxSetEnabledReferenceUris",  xmldsig_set_enabledReferenceUris,       METH_VARARGS},
  {"dsigCtxGetStatus",                xmldsig_get_status,                     METH_VARARGS},
  {"dsigCtxGetKeyInfoReadCtx",        xmldsig_get_keyInfoReadCtx,             METH_VARARGS},
  {"dsigCtxGetSignedInfoReferences",  xmldsig_get_signedInfoReferences,       METH_VARARGS},

  /* crypto.h */
  {"cryptoAppInit",                    xmlsec_CryptoAppInit,                    METH_VARARGS},
  {"cryptoAppKeyLoad",                 xmlsec_CryptoAppKeyLoad,                 METH_VARARGS},
  {"cryptoAppShutdown",                xmlsec_CryptoAppShutdown,                METH_VARARGS},
  {"cryptoAppDefaultKeysMngrInit",     xmlsec_CryptoAppDefaultKeysMngrInit,     METH_VARARGS},
  {"cryptoAppDefaultKeysMngrAdoptKey", xmlsec_CryptoAppDefaultKeysMngrAdoptKey, METH_VARARGS},
  {"cryptoAppKeysMngrCertLoad",        xmlsec_CryptoAppKeysMngrCertLoad,        METH_VARARGS},
  {"cryptoInit",     xmlsec_CryptoInit,     METH_VARARGS},
  {"cryptoShutdown", xmlsec_CryptoShutdown, METH_VARARGS},
  {"transformDsaSha1Id", xmlsec_TransformDsaSha1Id, METH_VARARGS},
  {"transformRsaSha1Id", xmlsec_TransformRsaSha1Id, METH_VARARGS},
  {"transformSha1Id",    xmlsec_TransformSha1Id,    METH_VARARGS},
  {"keyDataDsaId",  xmlsec_KeyDataDsaId,  METH_VARARGS},
  {"keyDataRsaId",  xmlsec_KeyDataRsaId,  METH_VARARGS},
  {"keyDataX509Id", xmlsec_KeyDataX509Id, METH_VARARGS},

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
  {"keyCreate",  xmlsec_KeyCreate,  METH_VARARGS},
  {"keyDestroy", xmlsec_KeyDestroy, METH_VARARGS},
  {"keyGetName", xmlsec_KeySetName, METH_VARARGS},
  {"keySetName", xmlsec_KeySetName, METH_VARARGS},
  /* keyinfo.h */
  {"keyInfoCtxCreate",     xmlsec_KeyInfoCtxCreate,     METH_VARARGS},
  {"keyInfoCtxDestroy",    xmlsec_KeyInfoCtxDestroy,    METH_VARARGS},
  {"keyInfoCtxInitialize", xmlsec_KeyInfoCtxInitialize, METH_VARARGS},
  {"keyInfoCtxFinalize",   xmlsec_KeyInfoCtxFinalize,   METH_VARARGS},
  {"keyInfoCtxReset",      xmlsec_KeyInfoCtxReset,      METH_VARARGS},
  {"getEnabledKeyData",    keyinfo_get_enabledKeyData,  METH_VARARGS},
  /* keysmngr.h */
  {"keysMngrCreate",  xmlsec_KeysMngrCreate,  METH_VARARGS},
  {"keysMngrDestroy", xmlsec_KeysMngrDestroy, METH_VARARGS},
  {"keysMngrFindKey", xmlsec_KeysMngrFindKey, METH_VARARGS},

  /* openssl/crypto.h, openssl/app.h */
  {"openSSLAppInit", xmlsec_OpenSSLAppInit, METH_VARARGS},
  {"openSSLInit",    xmlsec_OpenSSLInit,    METH_VARARGS},
  {NULL, NULL} /* End of Methods Sentinel */
};

void initxmlsecmod(void) {
  PyObject *m, *d;
  
  m = Py_InitModule("xmlsecmod", xmlsec_methods);
  d = PyModule_GetDict(m);
  xmlsec_error = PyErr_NewException("xmlsec.error", NULL, NULL);
  PyDict_SetItemString(d, "error", xmlsec_error);
}
