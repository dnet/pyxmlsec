#! /usr/bin/env python

"""
PyXMLSec - A Python binding for XML Security library (XMLSec)

$Id$

Copyright (C) 2003
http://

Author: Valery Febvre <vfebvre@easter-eggs.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
"""

import libxml2
import libxslt

import xmlsecmod
from xmlsec_strings import *

def init():
    return xmlsecmod.init()
def findNode(parent, name, ns):
    ret = xmlsecmod.findNode(parent, name, ns)
    if ret == None:
        return None
    return libxml2.xmlNode(_obj=ret)
def shutdown():
    return xmlsecmod.shutdown()

def cryptoAppInit(config=None):
    return xmlsecmod.cryptoAppInit(config)
def cryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx):
    ret = xmlsecmod.cryptoAppKeyLoad(filename, format, pwd,
                                     pwdCallback, pwdCallbackCtx)
    if ret is None: raise parserError('xmlSecCryptoAppKeyLoad() failed')
    return Key(_obj=ret)
def cryptoAppDefaultKeysMngrInit(mngr):
    return xmlsecmod.cryptoAppDefaultKeysMngrInit(mngr)
def cryptoAppDefaultKeysMngrAdoptKey(mngr, key):
    return xmlsecmod.cryptoAppDefaultKeysMngrAdoptKey(mngr, key)
def cryptoAppKeysMngrCertLoad(mngr, filename, format, type):
    return xmlsecmod.cryptoAppKeysMngrCertLoad(mngr, filename,
                                               format, type)
def cryptoAppShutdown():
    return xmlsecmod.cryptoAppShutdown()

def cryptoInit():
    return xmlsecmod.cryptoInit()
def cryptoShutdown():
    return xmlsecmod.cryptoShutdown()

## Transforms Ids methods
transformInclC14NId  = xmlsecmod.transformInclC14NId()
transformExclC14NId  = xmlsecmod.transformExclC14NId()
transformEnvelopedId = xmlsecmod.transformEnvelopedId()
transformDsaSha1Id   = xmlsecmod.transformDsaSha1Id()
transformRsaSha1Id   = xmlsecmod.transformRsaSha1Id()
transformSha1Id      = xmlsecmod.transformSha1Id()
## Key data ids methods
keyDataDsaId  = xmlsecmod.keyDataDsaId()
keyDataRsaId  = xmlsecmod.keyDataRsaId()
keyDataX509Id = xmlsecmod.keyDataX509Id()

TransformUriTypeNone         = 0x0000 # The URI type is unknown or not set.
TransformUriTypeEmpty        = 0x0001 # The empty URI ("") type.
TransformUriTypeSameDocument = 0x0002 # The smae document ("#...") but not empty ("") URI type.	
TransformUriTypeLocal        = 0x0004 # The local URI ("file:///....") type.
TransformUriTypeRemote       = 0x0008 # The remote URI type.
TransformUriTypeAny          = 0xFFFF # Any URI type.

class DSigCtx:
    def __init__(self, keysMngr=None, _obj=None):
        """
        Creates <dsig:Signature/> element processing context. The caller is
        responsible for destroying returend object by calling destroy method.
        keysMngr : the keys manager.
        Returns  : newly allocated context object or None if an error occurs."""
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.dsigCtxCreate(keysMngr)
        if self._o is None: raise parserError('xmlSecDSigCtxCreate() failed')
    def __repr__(self):
        return "<xmlSecDSigCtx object at 0x%x>" % id (self)
    #def get_flags(self):
    #    return self._o.flags
    #flags = property(get_flags, None, None, "the XML Digital Signature processing flags")
    def destroy(self):
        """
        Destroy context object (<dsig:Signature/> element processing context)."""
        return xmlsecmod.dsigCtxDestroy(self)
    def sign(self, tmpl):
        """
        Signs the data as described in tmpl node.
        tmpl : the pointer to <dsig:Signature/> node with signature template."""
        return xmlsecmod.dsigCtxSign(self, tmpl)
    def verify(self, node):
        """
        Validates signature in the node. The verification result is returned
        in status member of the dsigCtx object.
        node    : the pointer with <dsig:Signature/> node.
        Returns : 0 on success (check status member of dsigCtx to get signature
        verification result) or a negative value if an error occurs."""
        return xmlsecmod.dsigCtxVerify(self, node)
    def enableReferenceTransform(self, transformId):
        """
        Enables transformId for <dsig:Reference/> elements processing.
        transformId : the transform Id klass.
        Returns     : 0 on success or a negative value if an error occurs."""
        return xmlsecmod.dsigCtxEnableReferenceTransform(self, transformId)
    def enableSignatureTransform(self, transformId):
        """
        Enables transformId for <dsig:SignedInfo/> element processing.
        transformId : the transform Id klass.
        Returns     : 0 on success or a negative value if an error occurs."""
        return xmlsecmod.dsigCtxEnableSignatureTransform(self, transformId)
    def setSignKey(self, key):
        """Sets signKey member."""
        self._o = xmlsecmod.dsigCtxSetSignKey(self, key)
    def setEnabledReferenceUris(self, value):
        """Sets enabledReferenceUris member."""
        self._o = xmlsecmod.dsigCtxSetEnabledReferenceUris(self, value)
    def getStatus(self):
        """Return status member."""
        return xmlsecmod.dsigCtxGetStatus(self)
    def getKeyInfoReadCtx(self):
        """Return keyInfoReadCtx member."""
        return KeyInfoCtx(_obj=xmlsecmod.dsigCtxGetKeyInfoReadCtx(self))
    def getSignedInfoReferences(self):
        """Return signedInfoReferences member."""
        return PtrList(_obj=xmlsecmod.dsigCtxGetSignedInfoReferences(self))

class PtrList:
    def __init__(self, id=None, _obj=None):
        """
        Creates new list object. Caller is responsible for freeing returned list
        by calling destroy method.
        id      : the list klass.
        Returns : newly allocated list or None if an error occurs."""
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.ptrListCreate(id)
        if self._o is None: raise parserError('xmlSecPtrListCreate() failed')
    def __repr__(self):
        return "<xmlSecPtrList object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys list."""
        return xmlsecmod.ptrListDestroy(self)
    def add(self, item):
        """
        Adds item to the end of the list.
        item    : the item.
        Returns : 0 on success or a negative value if an error occurs."""
        return xmlsecmod.ptrListAdd(self, item)
    def getSize(self):
        """
        Gets list size.
        Returns : the number of itmes in list."""
        return xmlsecmod.ptrListGetSize(self)

class TmplSignature(libxml2.xmlNode):
    def __init__(self, doc, c14nMethodId, signMethodId, id=None, _obj=None):
        """
        Creates new <dsig:Signature/> node with the mandatory <dsig:SignedInfo/>,
        <dsig:CanonicalizationMethod/>, <dsig:SignatureMethod/> and
        <dsig:SignatureValue/> children and sub-children. The application is
        responsible for inserting the returned node in the XML document.
        doc          : the pointer to signature document or None; in the second
        case, application must later call libxml2 setTreeDoc function to ensure
        that all the children nodes have correct pointer to XML document.
        c14nMethodId : the signature canonicalization method.
        signMethodId : the signature method.
        id           : the node id (may be None).
        Returns      : the pointer to newly created <dsig:Signature/> node or
        None if an error occurs."""
        if _obj != None:
            self._o = _obj
            return
        _obj = xmlsecmod.tmplSignatureCreate(doc, c14nMethodId,
                                             signMethodId, id)
        if _obj is None: raise parserError('xmlSecTmplSignatureCreate() failed')
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplSignature object (%s) at 0x%x>" % (self.name, id(self))
    def addReference(self, digestMethodId, id=None, uri=None, type=None):
        """
        Adds <dsig:Reference/> node with given URI (uri), Id (id) and Type
        (type) attributes and the required children <dsig:DigestMethod/> and
        <dsig:DigestValue/> to the <dsig:SignedInfo/> child of node.
        digestMethodId : the reference digest method.
        id             : the node id (may be None).
        uri            : the reference node uri (may be None).
        type           : the reference node type (may be None).
        Returns        : the newly created <dsig:Reference/> node or None if
        an error occurs."""
        return TmplReference(xmlsecmod.tmplSignatureAddReference(self,
                                                                 digestMethodId,
                                                                 id, uri, type))
    def ensureKeyInfo(self, id=None):
        """
        Adds (if necessary) <dsig:KeyInfo/> node to the <dsig:Signature/> node.
        id : the node id (may be None).
        Returns : the newly created <dsig:KeyInfo/> node or None if an error
        occurs."""
        return TmplKeyInfo(xmlsecmod.tmplSignatureEnsureKeyInfo(self, id))


class TmplKeyInfo(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplKeyInfo object (%s) at 0x%x>" % (self.name,
                                                            id (self))
    def addKeyName(self, name=None):
        """
        Adds <dsig:KeyName/> node to the <dsig:KeyInfo/> node.
        name    : the key name (optional).
        Returns : the pointer to the newly created <dsig:KeyName/> node or None
        if an error occurs."""
        return TmplKeyName(xmlsecmod.tmplKeyInfoAddKeyName(self, name))


class TmplKeyName(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplKeyName object (%s) at 0x%x>" % (self.name, id (self))


class TmplReference(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplReference object (%s) at 0x%x>" % (self.name,
                                                              id (self))
    def addTransform(self, transformId):
        """
        Adds <dsig:Transform/> node to the <dsig:Reference/> node.
        transformId : the transform method id.
        Returns     : the newly created <dsig:Transform/> node or None if
        an error occurs."""
        return xmlsecmod.tmplReferenceAddTransform(self, transformId)


KeyDataTypeUnknown   = 0x0000 # The key data type is unknown (same as #xmlSecKeyDataTypeNone)
KeyDataTypeNone	     = KeyDataTypeUnknown
KeyDataTypePublic    = 0x0001 # The key data contain a public key.
KeyDataTypePrivate   = 0x0002 # The key data contain a private key.
KeyDataTypeSymmetric = 0x0004 # The key data contain a symmetric key.
KeyDataTypeSession   = 0x0008 # The key data contain session key (one time key, not stored in keys manager).
KeyDataTypePermanent = 0x0010 # The key data contain permanent key (stored in keys manager).
KeyDataTypeTrusted   = 0x0100 # The key data is trusted.
KeyDataTypeAny       = 0xFFFF # Any key data.

KeyDataFormatUnknown  = 0 # the key data format is unknown.
KeyDataFormatBinary   = 1 # the binary key data.
KeyDataFormatPem      = 2 # the PEM key data (cert or public/private key).
KeyDataFormatDer      = 3 # the DER key data (cert or public/private key).
KeyDataFormatPkcs8Pem = 4 # the PKCS#8 PEM private key.
KeyDataFormatPkcs8Der = 5 # the PKCS#8 DER private key.
class Key:
    def __init__(self, _obj=None):
	if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.keyCreate()
        if self._o is None: raise parserError('xmlSecKeyCreate() failed')
    def __repr__(self):
        return "<xmlSecKey object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys the key"""
        xmlsecmod.keyDestroy(self)
    def setName(self, name):
        """
        Sets key name (see also getName function).
        name    : the new key name.
        Returns : 0 on success or a negative value if an error occurs."""
        return xmlsecmod.keySetName(self, name)

class KeyInfoCtx:
    def __init__(self, _obj=None):
	if _obj != None:
            self._o = _obj
            return
        self._o = None
    def __repr__(self):
        return "<xmlSecKeyInfoCtx object at 0x%x>" % id (self)
    def getEnabledKeyData(self):
        """Return enabledKeyData member."""
        return PtrList(None, _obj=xmlsecmod.getEnabledKeyData(self))

class KeysMngr:
    def __init__(self, _obj=None):
	if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.keysMngrCreate()
        if self._o is None: raise parserError('xmlSecKeysMngrCreate() failed')
    def __repr__(self):
        return "<xmlSecKeysMngr object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys keys manager"""
        xmlsecmod.keysMngrDestroy(self)
    def findKey(self, name, key_info_ctx):
        """
        Lookups key in the keys manager keys store. The caller is responsible
        for destroying the returned key using destroy method.
        name       : the desired key name.
        keyInfoCtx : the pointer to <dsig:KeyInfo/> node processing context.
        Returns    : the pointer to a key or None if key is not found or
        an error occurs."""
        _obj = xmlsecmod.keysMngrFindKey(self, name, key_info_ctx)
        if _obj is None: raise parserError('xmlSecKeysMngrFindKey() failed')
        return Key(_obj=_obj)
