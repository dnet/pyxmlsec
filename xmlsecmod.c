/* pyxmlsec -- A Python binding for XML Security library (XMLSec)
 *
 * Copyright (C) 2003 Valery Febvre <vfebvre@easter-eggs.com>
 * http://
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
#include "keys.h"
#include "crypto.h"
#include "openssl.h"

static PyMethodDef xmlsec_methods[] = {
  /* xmlsec.h */
  {"init",     xmlsec_Init,     METH_VARARGS},
  {"shutdown", xmlsec_Shutdown, METH_VARARGS},

  /* xmltree.h */
  {"findNode", xmlsec_FindNode, METH_VARARGS},

  /* xmldsig.h */
  {"dsigCtxCreate",     xmlsec_DSigCtxCreate,  METH_VARARGS},
  {"dsigCtxDestroy",    xmlsec_DSigCtxDestroy, METH_VARARGS},
  {"dsigCtxSign",       xmlsec_DSigCtxSign,    METH_VARARGS},
  {"dsigCtxVerify",     xmlsec_DSigCtxVerify,  METH_VARARGS},
  {"dsigCtxSetSignKey", xmldsig_set_signKey,   METH_VARARGS},
  {"dsigCtxGetStatus",  xmldsig_get_status,    METH_VARARGS},

  /* crypto.h */
  {"cryptoAppInit",     xmlsec_CryptoAppInit,     METH_VARARGS},
  {"cryptoAppKeyLoad",  xmlsec_CryptoAppKeyLoad,  METH_VARARGS},
  {"cryptoAppShutdown", xmlsec_CryptoAppShutdown, METH_VARARGS},
  {"cryptoInit",        xmlsec_CryptoInit,        METH_VARARGS},
  {"cryptoShutdown",    xmlsec_CryptoShutdown,    METH_VARARGS},

  /* templates.h */
  {"tmplSignatureCreate",        xmlsec_TmplSignatureCreate,        METH_VARARGS},
  {"tmplSignatureAddReference",  xmlsec_TmplSignatureAddReference,  METH_VARARGS},
  {"tmplReferenceAddTransform",  xmlsec_TmplReferenceAddTransform,  METH_VARARGS},
  {"tmplSignatureEnsureKeyInfo", xmlsec_TmplSignatureEnsureKeyInfo, METH_VARARGS},
  {"tmplKeyInfoAddKeyName",      xmlsec_TmplKeyInfoAddKeyName,      METH_VARARGS},

  /* keys.h */
  {"keyCreate",  xmlsec_KeyCreate,  METH_VARARGS},
  {"keySetName", xmlsec_KeySetName, METH_VARARGS},

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
