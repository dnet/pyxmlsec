#! /usr/bin/env python

import libxml2
import libxslt

import xmlsecmod
from strings import *

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
def dsigCtxSign(dsigCtx, tmpl):
    return xmlsecmod.dsigCtxSign(dsigCtx, tmpl)

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

def tmplSignatureCreate(doc, c14nMethodId, signMethodId, id):
    ret = xmlsecmod.tmplSignatureCreate(doc, c14nMethodId, signMethodId, id)
    if ret is None: raise parserError('xmlSecTmplSignatureCreate() failed')
    return TmplSignature(_obj=ret)

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
    def sign(self, tmpl):
        return xmlsecmod.dsigCtxSign(self, tmpl)
    def setSignKey(self, signKey):
        self._o = xmlsecmod.dsigCtxSetSignKey(self, signKey)

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
