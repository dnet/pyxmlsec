#! /usr/bin/env python
#
# $Id$
#
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
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

"""
PyXMLSec - Python bindings for XML Security library (XMLSec)
Copyright (C) 2003 Easter-eggs, Valery Febvre

Author   : Valery Febvre <vfebvre@easter-eggs.com>
Homepage : http://pyxmlsec.labs.libre-entreprise.org

PyXMLSec was originally developped for Glasnost project.
http://glasnost.entrouvert.org

In 2003, the development of Glasnost is supported by the French Department of
Economy, Finance and Industry, as part of the UCIP - Collective Use of Internet
by SMEs - programme.
"""

import libxml2
import libxslt

import xmlsecmod
from xmlsec_strings import *

###############################################################################
# xmlsec.h
###############################################################################
def init():
    return xmlsecmod.init()
def shutdown():
    return xmlsecmod.shutdown()
def checkVersionExact():
    return xmlsecmod.checkVersionExact()
def checkVersion():
    return xmlsecmod.checkVersion()

###############################################################################
# app.h
###############################################################################
# Crypto Init/Shutdown
def cryptoInit():
    return xmlsecmod.cryptoInit()
def cryptoShutdown():
    return xmlsecmod.cryptoShutdown()
def cryptoKeysMngrInit(mngr):
    return xmlsecmod.cryptoKeysMngrInit(mngr)
# Key data ids methods
keyDataDesId  = xmlsecmod.keyDataDesId()
keyDataDsaId  = xmlsecmod.keyDataDsaId()
keyDataRsaId  = xmlsecmod.keyDataRsaId()
keyDataX509Id = xmlsecmod.keyDataX509Id()
# Crypto Transforms Ids methods
transformAes128CbcId     = xmlsecmod.transformAes128CbcId()
transformAes192CbcId     = xmlsecmod.transformAes192CbcId()
transformAes256CbcId     = xmlsecmod.transformAes256CbcId()
transformKWAes128Id      = xmlsecmod.transformKWAes128Id()
transformKWAes192Id      = xmlsecmod.transformKWAes192Id()
transformKWAes256Id      = xmlsecmod.transformKWAes256Id()
transformDes3CbcId       = xmlsecmod.transformDes3CbcId()
transformKWDes3Id        = xmlsecmod.transformKWDes3Id()
transformDsaSha1Id       = xmlsecmod.transformDsaSha1Id()
transformHmacSha1Id      = xmlsecmod.transformHmacSha1Id()
transformHmacRipemd160Id = xmlsecmod.transformHmacRipemd160Id()
transformHmacMd5Id       = xmlsecmod.transformHmacMd5Id()
transformRipemd160Id     = xmlsecmod.transformRipemd160Id()
transformRsaSha1Id       = xmlsecmod.transformRsaSha1Id()
transformRsaPkcs1Id      = xmlsecmod.transformRsaPkcs1Id()
transformRsaOaepId       = xmlsecmod.transformRsaOaepId()
transformSha1Id          = xmlsecmod.transformSha1Id()
# High level routines form xmlsec command line utility
def cryptoAppInit(config=None):
    return xmlsecmod.cryptoAppInit(config)
def cryptoAppKeyLoad(filename, format, pwd, pwdCallback, pwdCallbackCtx):
    ret = xmlsecmod.cryptoAppKeyLoad(filename, format, pwd,
                                     pwdCallback, pwdCallbackCtx)
    if ret is None: raise parserError('xmlSecCryptoAppKeyLoad() failed')
    return Key(_obj=ret)
def cryptoAppDefaultKeysMngrInit(mngr):
    return xmlsecmod.cryptoAppDefaultKeysMngrInit(mngr)
def cryptoAppDefaultKeysMngrLoad(mngr, uri):
    return xmlsecmod.cryptoAppDefaultKeysMngrLoad(mngr, uri)
def cryptoAppDefaultKeysMngrSave(mngr, filename, type):
    return xmlsecmod.cryptoAppDefaultKeysMngrSave(mngr, filename, type)
def cryptoAppDefaultKeysMngrAdoptKey(mngr, key):
    return xmlsecmod.cryptoAppDefaultKeysMngrAdoptKey(mngr, key)
def cryptoAppKeysMngrCertLoad(mngr, filename, format, type):
    return xmlsecmod.cryptoAppKeysMngrCertLoad(mngr, filename, format, type)
def cryptoAppShutdown():
    return xmlsecmod.cryptoAppShutdown()

###############################################################################
# parse.h
###############################################################################
# The XML Parser transform Id method
transformXmlParserId = xmlsecmod.transformXmlParserId()
def parseFile(filename):
    """
    Loads XML Doc from file filename. We need a special version because of c14n
    issue. The code is copied from xmlSAXParseFileWithData() function.
    filename : the filename.
    Returns  : the loaded XML document or None if an error occurs.
    """
    return xmlsecmod.parseFile(filename)
def parseMemory(buffer, size, recovery):
    """
    Loads XML Doc from memory. We need a special version because of c14n issue.
    The code is copied from xmlSAXParseMemory() function.
    buffer   : the input buffer.
    size     : the input buffer size.
    recovery : the flag.
    Returns  : the loaded XML document or None if an error occurs.
    """
    return xmlsecmod.parseMemory(buffer, size, recovery)
def parseMemoryExt(prefix, prefixSize, buffer, bufferSize, postfix, postfixSize):
    """
    Loads XML Doc from 3 chunks of memory: prefix, buffer and postfix.
    prefix      : the first part of the input.
    prefixSize  : the size of the first part of the input.
    buffer      : the second part of the input.
    bufferSize  : the size of the second part of the input.
    postfix     : the third part of the input.
    postfixSize : the size of the third part of the input.
    Returns     : the loaded XML document or None if an error occurs.
    """
    return xmlsecmod.parseMemoryExt(prefix, prefixSize, buffer, bufferSize,
                                    postfix, postfixSize)

###############################################################################
# x509.h
###############################################################################
# <dsig:X509Certificate/> node found or would be written back.
X509DATA_CERTIFICATE_NODE  = 0x00000001
# <dsig:X509SubjectName/> node found or would be written back.
X509DATA_SUBJECTNAME_NODE  = 0x00000002
# <dsig:X509IssuerSerial/> node found or would be written back.
X509DATA_ISSUERSERIAL_NODE = 0x00000004
# <dsig:/X509SKI> node found or would be written back.
X509DATA_SKI_NODE          = 0x00000008
# <dsig:X509CRL/> node found or would be written back.
X509DATA_CRL_NODE          = 0x00000010
# Default set of nodes to write in case of empty <dsig:X509Data/> node template.
X509DATA_DEFAULT = X509DATA_CERTIFICATE_NODE | X509DATA_CRL_NODE
def x509DataGetNodeContent(node, deleteChildren, keyInfoCtx):
    """
    Reads the contents of <dsig:X509Data/> node and returns it as a bits mask.
    node           : the <dsig:X509Data/> node.
    deleteChildren : the flag that indicates whether to remove node children
    after reading.
    keyInfoCtx     : the <dsig:KeyInfo/> node processing context.
    Returns        : the bit mask representing the <dsig:X509Data/> node content
    or a negative value if an error occurs.
    """
    return xmlsecmod.x509DataGetNodeContent(node, deleteChildren, keyInfoCtx)

###############################################################################
# xmltree.h
###############################################################################
def nodeGetName(node):
    return xmlsecmod.nodeGetName(node)
def getNodeNsHref(cur):
    return xmlsecmod.getNodeNsHref(cur)
def checkNodeName(cur, name, ns=None):
    return xmlsecmod.checkNodeName(cur, name, ns)
def getNextElementNode(cur):
    _obj = xmlsecmod.getNextElementNode(cur)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def findChild(parent, name, ns=None):
    _obj = xmlsecmod.findChild(parent, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def findParent(cur, name, ns=None):
    _obj = xmlsecmod.findParent(cur, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def findNode(parent, name, ns=None):
    _obj = xmlsecmod.findNode(parent, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def addChild(parent, name, ns=None):
    _obj = xmlsecmod.addChild(parent, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def addNextSibling(node, name, ns=None):
    _obj = xmlsecmod.addNextSibling(node, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def addPrevSibling(node, name, ns=None):
    _obj = xmlsecmod.addPrevSibling(node, name, ns)
    if _obj == None:
        return None
    return libxml2.xmlNode(_obj=_obj)
def replaceNode(node, newNode):
    return xmlsecmod.replaceNode(node, newNode)
def replaceContent(node, newNode):
    return xmlsecmod.replaceContent(node, newNode)
def replaceNodeBuffer(node, buffer, size):
    return xmlsecmod.replaceNodeBuffer(node, buffer, size)
def addIDs(doc, cur, ids):
    xmlsecmod.addIDs(doc, cur, ids)
def createTree(rootNodeName, rootNodeNs):
    return libxml2.xmlDoc(_obj=xmlsecmod.createTree(rootNodeName, rootNodeNs))
def isEmptyNode(node):
    return xmlsecmod.isEmptyNode(node)
def isEmptyString(str):
    return xmlsecmod.isEmptyString(str)
def isHex(c):
    return xmlsecmod.isHex(c)
def getHex(c):
    return xmlsecmod.getHex(c)

###############################################################################
# transforms.h
###############################################################################
transformInclC14NId  = xmlsecmod.transformInclC14NId()
transformExclC14NId  = xmlsecmod.transformExclC14NId()
transformEnvelopedId = xmlsecmod.transformEnvelopedId()
# Transform URIs types
TransformUriTypeNone         = 0x0000 # The URI type is unknown or not set.
TransformUriTypeEmpty        = 0x0001 # The empty URI ("") type.
TransformUriTypeSameDocument = 0x0002 # The same document ("#...") but not empty ("") URI type.	
TransformUriTypeLocal        = 0x0004 # The local URI ("file:///....") type.
TransformUriTypeRemote       = 0x0008 # The remote URI type.
TransformUriTypeAny          = 0xFFFF # Any URI type.

###############################################################################
# membuf.h
###############################################################################
# The Memory Buffer transform Id method
transformMemBufId = xmlsecmod.transformMemBufId()
def transformMemBufGetBuffer(transform):
    """
    Gets the memory buffer transform buffer.
    transform : the memory buffer transform.
    Returns   : the transform's buffer. 
    """
    return xmlsecmod.transformMemBufGetBuffer(transform)

###############################################################################
# base64.h
###############################################################################
BASE64_LINESIZE = 64 # The default maximum base64 encoded line size.
# Standalone functions to do base64 encode/decode "at once"
def base64Encode(buf, len, columns):
    # TODO : xmlfree on return buf ???
    """
    Encodes the data from input buffer.
    buf     : the input buffer.
    len     : the input buffer size.
    columns : the output max line length (if 0 then no line breaks would be inserted)
    Returns : a string with base64 encoded data or None if an error occurs.
    """
    return xmlsecmod.base64Encode(buf, len, columns)
def base64Decode(str, buf, len):
    """
    Decodes input base64 encoded string and puts result into the output buffer.
    str     : the input buffer with base64 encoded string
    buf     : the output buffer
    len     : the output buffer size
    Returns : the number of bytes written to the output buffer or a negative
    value if an error occurs 
    """
    return xmlsecmod.base64Decode(str, buf, len)
class Base64Ctx:
    def __init__(self, encode, columns, _obj=None):
        """
        Allocates and initializes new base64 context.
        encode  : the encode/decode flag (1 - encode, 0 - decode)
        columns : the max line length.
        Returns : the newly created xmlSecBase64Ctx structure or None if an error occurs.
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.base64CtxCreate(encode, columns)
        if self._o is None: raise parserError('xmlSecBase64CtxCreate() failed')
    def destroy(self):
        """Destroys base64 context."""
        xmlsecmod.base64CtxDestroy(self)
    def initialize(self, encode, columns):
        """
        Initializes new base64 context.
        encode  : the encode/decode flag (1 - encode, 0 - decode)
        columns : the max line length.
        Returns : 0 on success and a negative value otherwise.
        """
        return xmlsecmod.base64CtxDestroy(self, encode, columns)
    def finalize(self):
        """Frees all the resources allocated by Base64 context."""
        xmlsecmod.base64CtxDestroy(self)
    def update(self, inBuf, inBufSize, outBuf, outBufSize):
        """
        Encodes or decodes the next piece of data from input buffer.
        inBuf      : the input buffer
        inBufSize  : the input buffer size
        outBuf     : the output buffer
        outBufSize : the output buffer size
        Returns    : the number of bytes written to output buffer
        or -1 if an error occurs.
        """
        return xmlsecmod.base64CtxUpdate(self, inBuf, inBufSize, outBuf, outBufSize)
    def final(self, outBuf, outBufSize):
        """
        Encodes or decodes the last piece of data stored in the context and
        finalizes the result.
        outBuf     : the output buffer
        outBufSize : the output buffer size
        Returns    : the number of bytes written to output buffer
        or -1 if an error occurs.
        """
        return xmlsecmod.base64CtxFinal(self, outBuf, outBufSize)

###############################################################################
# xmlenc.h
###############################################################################
xmlEncCtxModeEncryptedData = 0 # the <enc:EncryptedData/> element processing.
xmlEncCtxModeEncryptedKey  = 1 # the <enc:EncryptedKey/> element processing.
class EncCtx:
    def __init__(self, keysMngr=None, _obj=None):
        """
        Creates <enc:EncryptedData/> element processing context. The caller is
        responsible for destroying returned object by calling destroy method.
        keysMngr : the keys manager.
        Returns  : newly allocated context object or None if an error occurs.
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.encCtxCreate(keysMngr)
        if self._o is None: raise parserError('xmlSecEncCtxCreate() failed')
    def destroy(self):
        """Destroys context object."""
        xmlsecmod.encCtxDestroy(self)
    def initialize(self, keysMngr):
        """
        Initializes <enc:EncryptedData/> element processing context. The caller
        is responsible for cleaing up returned object by calling finalize method.
        keysMngr : the keys manager.
        Returns  : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxInitialize(self, keysMngr)
    def finalize(self):
        """Cleans up context object."""
        return xmlsecmod.encCtxFinalize(self)
    def copyUserPref(self, src):
        """
        Copies user preference from src context.
        src     : the source context.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxCopyUserPref(self, src)
    def reset(self):
        """Resets enc context object, user settings are not touched."""
        return xmlsecmod.encCtxReset(self)
    def binaryEncrypt(self, tmpl, data, dataSize):
        """
        Encrypts data according to template tmpl.
        tmpl     : the <enc:EncryptedData/> template node.
        data     : the binary buffer.
        dataSize : the data buffer size.
        Returns  : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxBinaryEncrypt(self, tmpl, data, dataSize)
    def xmlEncrypt(self, tmpl, node):
        """
        Encrypts node according to template tmpl. If requested, node is replaced
        with result <enc:EncryptedData/> node.
        tmpl    : the <enc:EncryptedData/> template node.
        node    : the node for encryption.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxXmlEncrypt(self, tmpl, node)
    def uriEncrypt(self, tmpl, uri):
        """
        Encrypts data from uri according to template tmpl.
        tmpl    : the <enc:EncryptedData/> template node.
        uri     : the URI.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxUriEncrypt(self, tmpl, uri)
    def decrypt(self, node):
        """
        Decrypts node and if necessary replaces node with decrypted data.
        node    : the <enc:EncryptedData/> node.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxDecrypt(self, node)
    def decryptToBuffer(self, node):
        """
        Decrypts node data to the encCtx buffer.
        node    : the <enc:EncryptedData/> node.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.encCtxDecryptToBuffer(self, node)
    def debugDump(self, output):
        """
        Prints the debug information about enc context to output.
        output : the path to output FILE.
        """
        xmlsecmod.encCtxDebugDump(self, output)
    def debugXmlDump(self):
        """
        Prints the debug information about enc context to output in XML format.
        output : the path to output FILE.
        """
        xmlsecmod.encCtxDebugXmlDump(self, output)
    def setEncKey(self, key):
        """Sets encKey member."""
        xmlsecmod.encCtxSetEncKey(self, key)
    def getResult(self):
        """Gets result member (Buffer)."""
        return Buffer(_obj=xmlsecmod.encCtxGetResult(self))
    def getResultBase64Encoded(self):
        """Gets resultBase64Encoded member."""
        return xmlsecmod.encCtxGetResultBase64Encoded(self)
    def getResultReplaced(self):
        """Gets resultReplaced member."""
        return xmlsecmod.encCtxGetResultReplaced(self)

###############################################################################
# buffer.h
###############################################################################
# The memory allocation mode (used by Buffer and List).
# the memory allocation mode that minimizes total allocated memory size.
AllocModeExact  = 0
# the memory allocation mode that tries to minimize the number of malloc calls.
AllocModeDouble = 1
class Buffer:
    def __init__(self, size=None, _obj=None):
        """
        Allocates and initalizes new memory buffer with given size. Caller is
        responsible for calling destroy method to free the buffer.
        size    : the initial buffer size.
        Returns : pointer to newly allocated buffer or None if an error occurs.
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.bufferCreate(size)
        if self._o is None: raise parserError('xmlSecBufferCreate() failed')
    def destroy(self):
        """Destroys buffer object."""
        return xmlsecmod.bufferDestroy(self)
    def initialize(self, size):
        """
        Initializes buffer object buf. Caller is responsible for calling
        finalize method to free allocated resources.
        size    : the initial buffer size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferInitialize(self, size)
    def finalize(self):
        """Frees allocated resource for a buffer intialized with initialize method."""
        xmlsecmod.bufferFinalize(self)
    def getData(self):
        """
        Gets buffer's data.
        Returns : buffer's data.
        """
        return xmlsecmod.bufferGetData(self)
    def setData(self, data, size):
        """
        Sets the value of the buffer to data.
        data    : the data.
        size    : the data size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferSetData(self, data, size)
    def getSize(self):
        """
        Gets the current buffer data size.
        Returns : the current data size.
        """
        return xmlsecmod.bufferGetSize(self)
    def setSize(self, size):
        """
        Sets new buffer data size. If necessary, buffer grows to have at least
        size bytes.
        size    : the new data size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferSetSize(self, size)
    def getMaxSize(self):
        """
        Gets the maximum (allocated) buffer size.
        Returns : the maximum (allocated) buffer size.
        """
        return xmlsecmod.bufferGetMaxSize(self)
    def setMaxSize(self, size):
        """
        Sets new buffer maximum size. If necessary, buffer grows to have at
        least size bytes.
        size    : the new maximum size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferSetMaxSize(self, size)
    def empty(self):
        """Empties the buffer."""
        xmlsecmod.bufferEmpty(self)
    def append(self, data, size):
        """
        Appends the data after the current data stored in the buffer.
        data    : the data.
        size    : the data size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferAppend(self, data, size)
    def prepend(self, data, size):
        """
        Prepends the data before the current data stored in the buffer.
        data    : the data.
        size    : the data size.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferPrepend(self, data, size)
    def removeHead(self, size):
        """
        Removes size bytes from the beginning of the current buffer.
        size    : the number of bytes to be removed.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferRemoveHead(self, size)
    def removeTail(self, size):
        """
        Removes size bytes from the end of current buffer.
        size    : the number of bytes to be removed.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferRemoveTail(self, size)
    def readFile(self, filename):
        """
        Reads the content of the file filename in the buffer.
        filename : the filename.
        Returns  : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferReadFile(self, filename)
    def base64NodeContentRead(self, node):
        """
        Reads the content of the node, base64 decodes it and stores the result
        in the buffer.
        node    : the node.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferBase64NodeContentRead(self, node)
    def base64NodeContentWrite(self, node, columns):
        """
        Sets the content of the node to the base64 encoded buffer data.
        node    : the node.
        columns : the max line size fro base64 encoded data.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.bufferBase64NodeContentWrite(self, node)
    def createOutputBuffer(self):
        """
        Creates new LibXML output buffer to store data in the buf. Caller is
        responsible for destroying buf when processing is done.
        Returns : newly allocated output buffer or None if an error occurs.
        """
        return libxml2.xmlOutputBuffer(_obj=xmlsecmod.bufferCreateOutputBuffer(self))

###############################################################################
# xmldsig.h
###############################################################################
# If this flag is set then <dsig:Manifests/> nodes will not be processed.
DSIG_FLAGS_IGNORE_MANIFESTS =            0x00000001
# If this flag is set then pre-digest buffer for <dsig:Reference/> child
# of <dsig:KeyInfo/> element will be stored in #xmlSecDSigCtx.
DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES = 0x00000002
# If this flag is set then pre-digest buffer for <dsig:Reference/> child
# of <dsig:Manifest/> element will be stored in #xmlSecDSigCtx.
DSIG_FLAGS_STORE_MANIFEST_REFERENCES =   0x00000004
# If this flag is set then pre-signature buffer for <dsig:SignedInfo/>
# element processing will be stored in #xmlSecDSigCtx.
DSIG_FLAGS_STORE_SIGNATURE =             0x00000008
# DSig processing status.
DSigStatusUnknown   = 0
DSigStatusSucceeded = 1
DSigStatusInvalid   = 2
class DSigCtx:
    def __init__(self, keysMngr=None, _obj=None):
        """
        Creates <dsig:Signature/> element processing context. The caller is
        responsible for destroying returned object by calling destroy method.
        keysMngr : the keys manager.
        Returns  : newly allocated context object or None if an error occurs.
        """
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
        Destroys context object (<dsig:Signature/> element processing context).
        """
        return xmlsecmod.dsigCtxDestroy(self)
    def initialize(self, mngr):
        """
        Initializes <dsig:Signature/> element processing context. The caller is
        responsible for cleaing up returned object by calling finalize method.
        keysMngr : the keys manager.
        Returns  : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.dsigCtxInitialize(self, mngr)
    def finalize(self):
        """Cleans up DSigCtx object."""
        xmlsecmod.dsigCtxFinalize(self)
    def sign(self, tmpl):
        """
        Signs the data as described in tmpl node.
        tmpl : the <dsig:Signature/> node with signature template.
        """
        return xmlsecmod.dsigCtxSign(self, tmpl)
    def verify(self, node):
        """
        Validates signature in the node. The verification result is returned
        in status member of the dsigCtx object.
        node    : the <dsig:Signature/> node.
        Returns : 0 on success (check status member of dsigCtx to get signature
        verification result) or a negative value if an error occurs.
        """
        return xmlsecmod.dsigCtxVerify(self, node)
    def enableReferenceTransform(self, transformId):
        """
        Enables transformId for <dsig:Reference/> elements processing.
        transformId : the transform Id klass.
        Returns     : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.dsigCtxEnableReferenceTransform(self, transformId)
    def enableSignatureTransform(self, transformId):
        """
        Enables transformId for <dsig:SignedInfo/> element processing.
        transformId : the transform Id klass.
        Returns     : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.dsigCtxEnableSignatureTransform(self, transformId)
    def getPreSignBuffer(self):
        """
        Gets the buffer with serialized <dsig:SignedInfo/> element just before
        signature calculation (valid if and only if
        DSIG_FLAGS_STORE_SIGNATURE context flag is set).
        Returns : 0 on success or a negative value if an error occurs.
        """
        return Buffer(_obj=xmlsecmod.dsigCtxGetPreSignBuffer(self))
    def debugDump(self, output):
        """
        Prints the debug information about dsigCtx to output.
        output : path of output file.
        """
        xmlsecmod.dsigCtxDebugDump(self, output)
    def debugXmlDump(self, output):
        """
        Prints the debug information about dsigCtx to output file in XML format.
        output : path of output file.
        """
        xmlsecmod.dsigCtxDebugXmlDump(self, output)
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
        return KeyInfoCtx(None, _obj=xmlsecmod.dsigCtxGetKeyInfoReadCtx(self))
    def getSignedInfoReferences(self):
        """Return signedInfoReferences member."""
        return PtrList(_obj=xmlsecmod.dsigCtxGetSignedInfoReferences(self))

# The possible <dsig:Reference/> node locations: in the <dsig:SignedInfo/> node
# or in the <dsig:Manifest/> node.
DSigReferenceOriginSignedInfo = 0
DSigReferenceOriginManifest   = 1
class DSigReferenceCtx:
    def __init__(self, dsigCtx=None, origin=None, _obj=None):
        """
        Creates new <dsig:Reference/> element processing context. Caller is
        responsible for destroying the returned context by calling destroy
        method.
        dsigCtx : the parent <dsig:Signature/> node processing context.
        origin  : the reference origin (<dsig:SignedInfo/> or <dsig:Manifest/> node).
        Returns : newly created context or None if an error occurs.
        """
        if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.dsigReferenceCtxCreate(dsigCtx, origin)
        if self._o is None: raise parserError('xmlSecDSigReferenceCtxCreate() failed')
    def __repr__(self):
        return "<xmlSecDSigReferenceCtx object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys <dsig:Reference/> element processing context object"""
        return xmlsecmod.dsigReferenceCtxDestroy(self)
    def initialize(self, dsigCtx, origin):
        """
        Initializes new <dsig:Reference/> element processing context. Caller is
        responsible for cleaning up the returned context by calling finalize method.
        dsigCtx : the parent <dsig:Signature/> node processing context.
        origin  : the reference origin (<dsig:SignedInfo/> or <dsig:Manifest/> node).
        Returns : 0 on succes or a negative value otherwise.
        """
        return xmlsecmod.dsigReferenceCtxInitialize(self, dsigCtx, origin)
    def finalize(self):
        """Cleans up <dsig:Reference/> element processing object."""
        xmlsecmod.dsigReferenceCtxFinalize(self)
    def processNode(self, node):
        """
        The Reference Element (http://www.w3.org/TR/xmldsig-core/sec-Reference)

        Reference is an element that may occur one or more times. It specifies a
        digest algorithm and digest value, and optionally an identifier of the
        object being signed, the type of the object, and/or a list of transforms
        to be applied prior to digesting. The identification (URI) and transforms
        describe how the digested content (i.e., the input to the digest method)
        was created. The Type attribute facilitates the processing of referenced
        data. For example, while this specification makes no requirements over
        external data, an application may wish to signal that the referent is a
        Manifest. An optional ID attribute permits a Reference to be referenced
        from elsewhere.
        node    : the <dsig:Reference/> node.
        Returns : 0 on succes or aa negative value otherwise.
        """
        return xmlsecmod.dsigReferenceCtxProcessNode(self, node)
    def getPreDigestBuffer(self):
        """
        Gets the results of <dsig:Reference/> node processing just before
        digesting (valid only if DSIG_FLAGS_STORE_SIGNEDINFO_REFERENCES or
        DSIG_FLAGS_STORE_MANIFEST_REFERENCES flags of signature context is set).
        Returns : the buffer or None if an error occurs.
        """
        return Buffer(_obj=xmlsecmod.dsigReferenceCtxGetPreDigestBuffer(self))
    def debugDump(self, output):
        """
        Prints the debug information about dsigCtx to output.
        output : path of output file.
        """
        xmlsecmod.dsigCtxDebugDump(self, output)
    def debugXmlDump(self, output):
        """
        Prints the debug information about dsigCtx to output file in XML format.
        output : path of output file.
        """
        xmlsecmod.dsigCtxDebugXmlDump(self, output)
        
###############################################################################
# list.h
###############################################################################
class PtrList:
    def __init__(self, id=None, _obj=None):
        """
        Creates new list object. Caller is responsible for freeing returned list
        by calling destroy method.
        id      : the list klass.
        Returns : newly allocated list or None if an error occurs.
        """
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
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.ptrListAdd(self, item)
    def getSize(self):
        """
        Gets list size.
        Returns : the number of itmes in list.
        """
        return xmlsecmod.ptrListGetSize(self)

###############################################################################
# templates.h
###############################################################################
class TmplSignature(libxml2.xmlNode):
    def __init__(self, doc, c14nMethodId, signMethodId, id=None, _obj=None):
        """
        Creates new <dsig:Signature/> node with the mandatory <dsig:SignedInfo/>,
        <dsig:CanonicalizationMethod/>, <dsig:SignatureMethod/> and
        <dsig:SignatureValue/> children and sub-children. The application is
        responsible for inserting the returned node in the XML document.
        doc          : the signature document or None; in the second case,
        application must later call libxml2 setTreeDoc function to ensure
        that all the children nodes have correct pointer to XML document.
        c14nMethodId : the signature canonicalization method.
        signMethodId : the signature method.
        id           : the node id (may be None).
        Returns      : the newly created <dsig:Signature/> node or None if an
        error occurs.
        """
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
        an error occurs.
        """
        return TmplReference(xmlsecmod.tmplSignatureAddReference(self,
                                                                 digestMethodId,
                                                                 id, uri, type))
    def addObject(self, id=None, mimeType=None, encoding=None):
        """
        Adds <dsig:Object/> node to the <dsig:Signature/> node.
        id       : the node id (may be None).
        mimeType : the object mime type (may be None).
        encoding : the object encoding (may be None).
        Returns  : the newly created <dsig:Object/> node or None if
        an error occurs.
        """
        return TmplObject(xmlsecmod.tmplSignatureAddObject(self, id, mimeType,
                                                           encoding))
    def getSignMethodNode(self):
        """
        Gets <dsig:SignatureMethod/> child of <dsig:KeyInfo/> node.
        Returns : <dsig:SignatureMethod /> node or None if an error occurs.
        """
        _obj = xmlsecmod.tmplSignatureGetSignMethodNode(self)
        if _obj is None:
            raise parserError('xmlSecTmplSignatureGetSignMethodNode() failed')
        return libxml2.xmlNode(_obj=_obj)
    def getC14NMethodNode(self):
        """
        Gets <dsig:CanonicalizationMethod/> child of <dsig:KeyInfo/> node.
        Returns : <dsig:CanonicalizationMethod /> node or None if an error occurs.
        """
        _obj = xmlsecmod.tmplSignatureGetC14NMethodNode(self)
        if _obj is None:
            raise parserError('xmlSecTmplSignatureGetC14NMethodNode() failed')
        return libxml2.xmlNode(_obj=_obj)
    def ensureKeyInfo(self, id=None):
        """
        Adds (if necessary) <dsig:KeyInfo/> node to the <dsig:Signature/> node.
        id : the node id (may be None).
        Returns : the newly created <dsig:KeyInfo/> node or None if an error
        occurs.
        """
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
        Returns : the newly created <dsig:KeyName/> node or None
        if an error occurs.
        """
        _obj = xmlsecmod.tmplKeyInfoAddKeyName(self, name)
        if _obj is None:
            raise parserError('xmlSecTmplKeyInfoAddKeyName() failed')
        return libxml2.xmlNode(_obj=_obj)
    def addKeyValue(self):
        """
        Adds <dsig:KeyValue/> node to the <dsig:KeyInfo/> node.
        Returns : the newly created <dsig:KeyValue/> node or None if an error
        occurs.
        """
        _obj = xmlsecmod.tmplKeyInfoAddKeyValue(self)
        if _obj is None:
            raise parserError('xmlSecTmplKeyInfoAddKeyValue() failed')
        return libxml2.xmlNode(_obj=_obj)
    def addX509Data(self):
        """
        Adds <dsig:X509Data/> node to the <dsig:KeyInfo/> node.
        Returns : the newly created <dsig:X509Data/> node or None if an error
        occurs.
        """
        _obj = xmlsecmod.tmplKeyInfoAddX509Data(self)
        if _obj is None:
            raise parserError('xmlSecTmplKeyInfoAddX509Data() failed')
        return libxml2.xmlNode(_obj=_obj)

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
        an error occurs.
        """
        _obj = xmlsecmod.tmplReferenceAddTransform(self, transformId)
        return libxml2.xmlNode(_obj=_obj)

class TmplObject(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplObject object (%s) at 0x%x>" % (self.name,
                                                           id (self))
    def addSignProperties(self, id=None, target=None):
        """
        Adds <dsig:SignatureProperties/> node to the <dsig:Object/> node.
        id      : the node id (may be None).
        target  : the Target (may be None).
        Returns : the newly created <dsig:SignatureProperties/> node or None
        if an error occurs.
        """
        _obj = xmlsecmod.tmplObjectAddSignProperties(self, id, target)
        if _obj is None:
            raise parserError('xmlSecTmplObjectAddSignProperties() failed')
        return libxml2.xmlNode(_obj=_obj)
    def addManifest(self, id=None):
        """
        Adds <dsig:Manifest/> node to the <dsig:Object/> node.
        id      : the node id (may be None).
        Returns : the newly created <dsig:Manifest/> node or None if
        an error occurs.
        """
        return TmplManifest(_obj=xmlsecmod.tmplObjectAddManifest(self, id))
        
class TmplManifest(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplManifest object (%s) at 0x%x>" % (self.name,
                                                             id (self))
    def addReference(self, digestMethodId, id=None, uri=None, type=None):
        """
        Adds <dsig:Reference/> node with specified URI (uri), Id (id) and Type
        (type) attributes and the required children <dsig:DigestMethod/> and
        <dsig:DigestValue/> to the <dsig:Manifest/> node.
        digestMethodId : the reference digest method.
        id             : the node id (may be None).
        uri            : the reference node uri (may be None).
        type           : the reference node type (may be None).
        Returns        : the newly created <dsig:Reference/> node or None if
        an error occurs.
        """
        _obj = xmlsecmod.tmplManifestAddReference(self, digestMethodId,
                                                  id, uri, type)
        return TmplReference(_obj=_obj)

class TmplEncData(libxml2.xmlNode):
    def __init__(self, doc=None, encMethodId=None, id=None, type=None,
                 mimeType=None, encoding=None, _obj=None):
        """
        Creates new <enc:EncryptedData /> node for encryption template.
        doc         : the signature document or None; in the later case,
        application must later call xmlSetTreeDoc to ensure that all the
        children nodes have correct pointer to XML document.
        encMethodId : the encryption method (may be None).
        id          : the Id attribute (optional).
        type        : the Type attribute (optional)
        mimeType    : the MimeType attribute (optional)
        encoding    : the Encoding attribute (optional)
        Returns     : the newly created <enc:EncryptedData/> node or
        None if an error occurs.
        """
        if _obj != None:
            self._o = _obj
            return
        _obj = xmlsecmod.tmplEncDataCreate(doc, encMethodId, id, type,
                                           mimeType, encoding)
        if _obj is None: raise parserError('xmlSecTmplEncDataCreate() failed')
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplEncData object (%s) at 0x%x>" % (self.name,
                                                            id (self))
    def ensureKeyInfo(self, id=None):
        """
        Adds <dsig:KeyInfo/> to the <enc:EncryptedData/> node encNode.
        id      : the Id attrbibute (optional).
        Returns : the newly created <dsig:KeyInfo/> node or None if an error occurs.
        """
        return xmlsecmod.tmplEncDataEnsureKeyInfo(self, id)
    def ensureEncProperties(self, id=None):
        """
        Adds <enc:EncryptionProperties/> node to the <enc:EncryptedData/> node
        encNode.
        id      : the Id attribute (optional).
        Returns : the newly created <enc:EncryptionProperties/> node or None if
        an error occurs.
        """
        return xmlsecmod.tmplEncDataEnsureEncProperties(self, id)
    def addEncProperty(self, id=None, target=None):
        """
        Adds <enc:EncryptionProperty/> node (and the parent
        <enc:EncryptionProperties/> node if required) to the
        <enc:EncryptedData/> node encNode.
        id      : the Id attribute (optional).
        target  : the Target attribute (optional).
        Returns : the newly created <enc:EncryptionProperty/> node or None if
        an error occurs.
        """
        return xmlsecmod.tmplEncDataAddEncProperty(self, id, target)
    def ensureCipherValue(self):
        """
        Adds <enc:CipherValue/> to the <enc:EncryptedData/> node encNode.
        Returns : the newly created <enc:CipherValue/> node or None if an error
        occurs.
        """
        return xmlsecmod.tmplEncDataEnsureCipherValue(self)
    def ensureCipherReference(self, uri=None):
        """
        Adds <enc:CipherReference/> node with specified URI attribute uri to
        the <enc:EncryptedData/> node encNode.
        uri     : the URI attribute (may be None).
        Returns : the newly created <enc:CipherReference/> node or None if an
        error occurs.
        """
        return TmplCipherReference(_obj=xmlsecmod.tmplEncDataEnsureCipherReference(self, uri))
    def getEncMethodNode(self):
        """
        Gets the <enc:EncrytpionMethod/> node.
        Returns : the <enc:EncryptionMethod /> node or None if an error occurs.
        """
        return xmlsecmod.tmplEncDataGetEncMethodNode(self)
    def addDataReference(self, uri=None):
        """
        Adds <enc:DataReference/> and the parent <enc:ReferenceList/> node
        (if needed).
        uri     : uri to reference (optional)
        Returns : the newly created <enc:DataReference/> node or None if an
        error occurs.
        """
        return xmlsecmod.tmplReferenceListAddDataReference(self, uri)
    def addKeyReference(self, uri=None):
        """
        Adds <enc:KeyReference/> and the parent <enc:ReferenceList/> node
        (if needed).
        uri     : uri to reference (optional)
        Returns : the newly created <enc:KeyReference/> node or None if an error
        occurs.
        """
        return xmlsecmod.tmplReferenceListAddKeyReference(self, uri)

class TmplCipherReference(libxml2.xmlNode):
    def __init__(self, _obj=None):
        self._o = None
        libxml2.xmlNode.__init__(self, _obj=_obj)
    def __repr__(self):
        return "<xmlSecTmplCipherReference object (%s) at 0x%x>" % (self.name,
                                                                    id (self))
    def addTransform(self, transformId):
        """
        Adds <dsig:Transform/> node (and the parent <dsig:Transforms/> node)
        with specified transform methods transform to the <enc:CipherReference/>
        child node of the <enc:EncryptedData/> node encNode.
        transformId         : the transform id.
        Returns             : the newly created <dsig:Transform/> node or None
        if an error occurs.
        """
        return xmlsecmod.tmplCipherReferenceAddTransform(self, transformId)

###############################################################################
# keys.h
###############################################################################
## Key data types
KeyDataTypeUnknown   = 0x0000 # The key data type is unknown (same as #xmlSecKeyDataTypeNone)
KeyDataTypeNone	     = KeyDataTypeUnknown
KeyDataTypePublic    = 0x0001 # The key data contain a public key.
KeyDataTypePrivate   = 0x0002 # The key data contain a private key.
KeyDataTypeSymmetric = 0x0004 # The key data contain a symmetric key.
KeyDataTypeSession   = 0x0008 # The key data contain session key (one time key, not stored in keys manager).
KeyDataTypePermanent = 0x0010 # The key data contain permanent key (stored in keys manager).
KeyDataTypeTrusted   = 0x0100 # The key data is trusted.
KeyDataTypeAny       = 0xFFFF # Any key data.
## Key usages
KeyUsageSign    = 0x0001 # Key for signing.
KeyUsageVerify  = 0x0002 # Key for signature verification.
KeyUsageEncrypt = 0x0004 # An encryption key.
KeyUsageDecrypt = 0x0008 # A decryption key.
KeyUsageAny     = 0xFFFF # Key can be used in any way.
## Key data formats
KeyDataFormatUnknown  = 0 # the key data format is unknown.
KeyDataFormatBinary   = 1 # the binary key data.
KeyDataFormatPem      = 2 # the PEM key data (cert or public/private key).
KeyDataFormatDer      = 3 # the DER key data (cert or public/private key).
KeyDataFormatPkcs8Pem = 4 # the PKCS#8 PEM private key.
KeyDataFormatPkcs8Der = 5 # the PKCS#8 DER private key.
def keyReadBuffer(dataId, buffer):
    """
    Reads the key value of klass dataId from a buffer.
    dataId  : the key value data klass.
    buffer  : the buffer that contains the binary data.
    Returns : newly created key or None if an error occurs.
    """
    return Key(_obj=xmlsecmod.keyReadBuffer(dataId, buffer))
def keyReadBinaryFile(dataId, filename):
    """
    Reads the key value of klass dataId from a binary file filename.
    dataId   : the key value data klass.
    filename : the key binary filename.
    Returns  : newly created key or None if an error occurs.
    """
    return Key(_obj=xmlsecmod.keyReadBinaryFile(dataId, filename))
def keyReadMemory(dataId, data, dataSize):
    """
    Reads the key value of klass dataId from a memory block data.
    dataId   : the key value data klass.
    data     : the memory containing the key
    dataSize : the size of the memory block
    Returns  : newly created key or None if an error occurs.
    """
    return Key(_obj=xmlsecmod.keyReadMemory(dataId, data, dataSize))
class Key:
    def __init__(self, _obj=None):
        """
        Allocates and initializes new key. Caller is responsible for freeing
        returned object with destroy method.
        Returns : the newly allocated key or None if an error occurs.
        """
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
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.keySetName(self, name)
    def getName(self):
        """
        Gets key name (see also setName function).
        Returns : key name.
        """
        return xmlsecmod.keyGetName(self)

class KeyReq:
    def __init__(self, keyId, keyType, keyUsage, keyBitsSize):
        self._o = xmlsecmod.keyReqCreate(keyId, keyType, keyUsage, keyBitsSize)
    def getKeyBitsSize(self):
        return self._o.keyBitsSize
    def initialize(self):
        """
        Initialize key requirements object. Caller is responsible for cleaning
        it with finalize method.
        Returns : 0 on success or a negative value if an error occurs.
        """
        return xmlsecmod.keyReqInitialize(self)
    def finalize(self):
        """Cleans the key requirements object."""
        xmlsecmod.keyReqFinalize(self)
    def reset(self):
        """Resets key requirements object for new key search."""
        xmlsecmod.keyReqReset(self)
    def matchKey(self, key):
        """
        Checks whether key matches key requirements.
        key     : the key.
        Returns : 1 if key matches requirements, 0 if not and a negative value
        if an error occurs.
        """
        return xmlsecmod.keyReqMatchKey(self, key)

###############################################################################
# keyinfo.h
###############################################################################
class KeyInfoCtx:
    def __init__(self, mngr=None, _obj=None):
        """
        Allocates and initializes <dsig:KeyInfo/> element processing context.
        Caller is responsible for freeing it by calling destroy method.
        mngr     : the keys manager (may be None).
        Returns  : the newly allocated object or None if an error occurs.
        """
	if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.keyInfoCtxCreate(mngr)
        if self._o is None: raise parserError('xmlSecKeyInfoCtxCreate() failed')
    def __repr__(self):
        return "<xmlSecKeyInfoCtx object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys the keyInfoCtx object"""
        return xmlsecmod.keyInfoCtxDestroy(self)
    def initialize(self, mngr=None):
        """
        Initializes <dsig:KeyInfo/> element processing context. Caller is
        responsible for cleaning it up by finalize method.
        mngr     : the keys manager (may be None).
        Returns  : 0 on success and a negative value if an error occurs.
        """
        return xmlsecmod.keyInfoCtxInitialize(self, mngr)
    def finalize(self):
        """Cleans up the keyInfoCtx initialized."""
        xmlsecmod.keyInfoCtxFinalize(self)
    def reset(self):
        """Resets the keyInfoCtx state. User settings are not changed."""
        xmlsecmod.keyInfoCtxReset(self)
    def getEnabledKeyData(self):
        """Return enabledKeyData member."""
        return PtrList(None, _obj=xmlsecmod.getEnabledKeyData(self))

###############################################################################
# keysmngr.h
###############################################################################
class KeysMngr:
    def __init__(self, _obj=None):
        """
        Creates new keys manager. Caller is responsible for freeing it with
        destroy method.
        Returns : the newly allocated keys manager or None if an error occurs.
        """
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
        keyInfoCtx : the <dsig:KeyInfo/> node processing context.
        Returns    : a key or None if key is not found or an error occurs.
        """
        _obj = xmlsecmod.keysMngrFindKey(self, name, key_info_ctx)
        if _obj is None: raise parserError('xmlSecKeysMngrFindKey() failed')
        return Key(_obj=_obj)
    # !!! come from app.h (not keysmngr.h) !!!
    def certLoad(self, filename, format, type):
        """
        Reads cert from filename and adds to the list of trusted
        or known untrusted certs in store.
        filename : the certificate file.
        format   : the certificate file format.
        type     : the flag that indicates is the certificate in filename
        trusted or not.
        Returns  : 0 on success or a negative value otherwise.
        """
        return xmlsecmod.cryptoAppKeysMngrCertLoad(self, filename, format, type)

simpleKeysStoreId = xmlsecmod.simpleKeysStoreId()
class KeyStore:
    def __init__(self, id, _obj=None):
        """
        Creates new store of the specified klass id. Caller is responsible for
        freeing the returned store by calling destroy method.
        id      : the key store klass.
        Returns : the newly allocated keys store or None if an error occurs.
        """
	if _obj != None:
            self._o = _obj
            return
        self._o = xmlsecmod.keyStoreCreate(id)
        if self._o is None: raise parserError('xmlSecKeyStoreCreate() failed')
    def __repr__(self):
        return "<xmlSecKeyStore object at 0x%x>" % id (self)
    def destroy(self):
        """Destroys the keys store"""
        xmlsecmod.keyStoreDestroy(self)
    def findKey(self, name, key_info_ctx):
        """
        Lookups key in the keys store. The caller is responsible for destroying
        the returned key using destroy method.
        name       : the desired key name.
        keyInfoCtx : the <dsig:KeyInfo/> node processing context.
        Returns    : a key or None if key is not found or an error occurs.
        """
        _obj = xmlsecmod.keyStoreFindKey(self, name, key_info_ctx)
        if _obj is None: raise parserError('xmlSecKeyStoreFindKey() failed')
        return Key(_obj=_obj)
