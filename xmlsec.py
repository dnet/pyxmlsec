#! /usr/bin/env python

# $Id$
#
# pyxmlsec -- A Python binding for XML Security library (XMLSec)
#
# Copyright (C) 2003
# http://
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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

def dsigCtxCreate(keyMngr=None):
    ret = xmlsecmod.dsigCtxCreate(keyMngr)
    if ret is None: raise parserError('xmlSecDSigCtxCreate() failed')
    return DSigCtx(_obj=ret)

def cryptoAppInit(config=None):
    return xmlsecmod.cryptoAppInit(config)
def cryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx):
    ret = xmlsecmod.cryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx)
    if ret is None: raise parserError('xmlSecTmplSignatureAddReference() failed')
    return Key(_obj=ret)
def cryptoAppShutdown():
    return xmlsecmod.cryptoAppShutdown()

def cryptoInit():
    return xmlsecmod.cryptoInit()
def cryptoShutdown():
    return xmlsecmod.cryptoShutdown()

def tmplSignatureCreate(doc, c14nMethodId, signMethodId, id=None):
    ret = xmlsecmod.tmplSignatureCreate(doc, c14nMethodId, signMethodId, id)
    if ret is None: raise parserError('xmlSecTmplSignatureCreate() failed')
    return TmplSignature(_obj=ret)

## Transforms Ids
transformExclC14NId  = xmlsecmod.transformExclC14NId()
transformEnvelopedId = xmlsecmod.transformEnvelopedId()
transformDsaSha1Id   = xmlsecmod.transformDsaSha1Id()
transformRsaSha1Id   = xmlsecmod.transformRsaSha1Id()
transformSha1Id      = xmlsecmod.transformSha1Id()


class DSigCtx:
    def __init__(self, _obj=None):
	if _obj != None:
           self._o = _obj
           return
        self._o = None
    def __repr__(self):
        return "<xmlSecDSigCtx object at 0x%x>" % id (self)
##     def get_flags(self):
##         return self._o.flags
    #flags = property(get_flags, None, None, "the XML Digital Signature processing flags")
    def destroy(self):
        return xmlsecmod.dsigCtxDestroy(self)
    def sign(self, tmpl):
        return xmlsecmod.dsigCtxSign(self, tmpl)
    def verify(self, node):
        return xmlsecmod.dsigCtxVerify(self, node)
    def setSignKey(self, signKey):
        self._o = xmlsecmod.dsigCtxSetSignKey(self, signKey)
    def getStatus(self):
        return xmlsecmod.dsigCtxGetStatus(self)


class TmplSignature(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplSignature object (%s) at 0x%x>" % (self.name, id (self))
    def addReference(self, digestMethodId, id=None, uri=None, type=None):
        return TmplReference(xmlsecmod.tmplSignatureAddReference(self, digestMethodId,
                                                                 id, uri, type))
    def ensureKeyInfo(self, id=None):
        return TmplKeyInfo(xmlsecmod.tmplSignatureEnsureKeyInfo(self, id))


class TmplKeyInfo(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplKeyInfo object (%s) at 0x%x>" % (self.name, id (self))
    def addKeyName(self, name=None):
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
        return "<xmlSecTmplReference object (%s) at 0x%x>" % (self.name, id (self))
    def addTransform(self, transformId):
        return xmlsecmod.tmplReferenceAddTransform(self, transformId)


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
        self._o = None
    def __repr__(self):
        return "<xmlSecKey object at 0x%x>" % id (self)
    def setName(self, name):
        return xmlsecmod.keySetName(self, name)
