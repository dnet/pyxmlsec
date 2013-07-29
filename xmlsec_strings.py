# $Id$
# 
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2013 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
# 
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
#
# ** 
# * XML Security Library (http://www.aleksey.com/xmlsec).
# *
# * All the string constants.
# *
# * This is free software; see Copyright file in the source
# * distribution for preciese wording.
# * 
# * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
# */



# *************************************************************************
# *
# * Global Namespaces
# *
# ************************************************************************/
Ns = "http://www.aleksey.com/xmlsec/2002"
DSigNs = "http://www.w3.org/2000/09/xmldsig#"
EncNs = "http://www.w3.org/2001/04/xmlenc#"
XkmsNs = "http://www.w3.org/2002/03/xkms#"
XPathNs = "http://www.w3.org/TR/1999/REC-xpath-19991116"
XPath2Ns = "http://www.w3.org/2002/06/xmldsig-filter2"
XPointerNs = "http://www.w3.org/2001/04/xmldsig-more/xptr"
Soap11Ns = "http://schemas.xmlsoap.org/soap/envelope/"
Soap12Ns = "http://www.w3.org/2002/06/soap-envelope"

# *************************************************************************
# *
# * DSig Nodes
# *
# ************************************************************************/
NodeSignature = "Signature"
NodeSignedInfo = "SignedInfo"
NodeCanonicalizationMethod = "CanonicalizationMethod"
NodeSignatureMethod = "SignatureMethod"
NodeSignatureValue = "SignatureValue"
NodeDigestMethod = "DigestMethod"
NodeDigestValue = "DigestValue"
NodeObject = "Object"
NodeManifest = "Manifest"
NodeSignatureProperties = "SignatureProperties"

# *************************************************************************
# *
# * Encryption Nodes
# *
# ************************************************************************/
NodeEncryptedData = "EncryptedData"
NodeEncryptionMethod = "EncryptionMethod"
NodeEncryptionProperties = "EncryptionProperties"
NodeEncryptionProperty = "EncryptionProperty"
NodeCipherData = "CipherData"
NodeCipherValue = "CipherValue"
NodeCipherReference = "CipherReference"
NodeReferenceList = "ReferenceList"
NodeDataReference = "DataReference"
NodeKeyReference = "KeyReference"

NodeCarriedKeyName = "CarriedKeyName"

TypeEncContent = "http://www.w3.org/2001/04/xmlenc#Content"
TypeEncElement = "http://www.w3.org/2001/04/xmlenc#Element"

# *************************************************************************
# *
# * XKMS Nodes
# *
# ************************************************************************/
XkmsServerRequestResultName = "result-response"
XkmsServerRequestStatusName = "status-request"
XkmsServerRequestLocateName = "locate-request"
XkmsServerRequestValidateName = "validate-request"
XkmsServerRequestCompoundName = "compound-request"

NodeResult = "Result"
NodeStatusRequest = "StatusRequest"
NodeStatusResult = "StatusResult"
NodeLocateRequest = "LocateRequest"
NodeLocateResult = "LocateResult"
NodeValidateRequest = "ValidateRequest"
NodeValidateResult = "ValidateResult"
NodeCompoundRequest = "CompoundRequest"
NodeCompoundResult = "CompoundResult"

NodeMessageExtension = "MessageExtension"
NodeOpaqueClientData = "OpaqueClientData"
NodeResponseMechanism = "ResponseMechanism"
NodeRespondWith = "RespondWith"
NodePendingNotification = "PendingNotification"
NodeQueryKeyBinding = "QueryKeyBinding"
NodeKeyUsage = "KeyUsage"
NodeUseKeyWith = "UseKeyWith"
NodeTimeInstant = "TimeInstant"
NodeRequestSignatureValue = "RequestSignatureValue"
NodeUnverifiedKeyBinding = "UnverifiedKeyBinding"
NodeValidityInterval = "ValidityInterval"
NodeStatus = "Status"
NodeValidReason = "ValidReason"
NodeInvalidReason = "InvalidReason"
NodeIndeterminateReason = "IndeterminateReason"

AttrService = "Service"
AttrNonce = "Nonce"
AttrOriginalRequestId = "OriginalRequestId"
AttrResponseLimit = "ResponseLimit"
AttrMechanism = "Mechanism["
AttrIdentifier = "Identifier"
AttrApplication = "Application"
AttrResultMajor = "ResultMajor"
AttrResultMinor = "ResultMinor"
AttrRequestId = "RequestId"
AttrNotBefore = "NotBefore"
AttrNotOnOrAfter = "NotOnOrAfter"
AttrTime = "Time"
AttrStatusValue = "StatusValue"

ResponseMechanismPending = "Pending"
ResponseMechanismRepresent = "Represent"
ResponseMechanismRequestSignatureValue = "RequestSignatureValue"

RespondWithKeyName = "KeyName"
RespondWithKeyValue = "KeyValue"
RespondWithX509Cert = "X509Cert"
RespondWithX509Chain = "X509Chain"
RespondWithX509CRL = "X509CRL"
RespondWithOCSP = "OCSP"
RespondWithRetrievalMethod = "RetrievalMethod"
RespondWithPGP = "PGP"
RespondWithPGPWeb = "PGPWeb"
RespondWithSPKI = "SPKI"
RespondWithPrivateKey = "PrivateKey"

StatusResultSuccess = "Success"
StatusResultFailed = "Failed"
StatusResultPending = "Pending"

KeyUsageEncryption = "Encryption"
KeyUsageSignature = "Signature"
KeyUsageExchange = "Exchange"

KeyBindingStatusValid = "Valid"
KeyBindingStatusInvalid = "Invalid"
KeyBindingStatusIndeterminate = "Indeterminate"

KeyBindingReasonIssuerTrust = "IssuerTrust"
KeyBindingReasonRevocationStatus = "RevocationStatus"
KeyBindingReasonValidityInterval = "ValidityInterval"
KeyBindingReasonSignature = "Signature"

ResultMajorCodeSuccess = "Success"
ResultMajorCodeVersionMismatch = "VersionMismatch"
ResultMajorCodeSender = "Sender"
ResultMajorCodeReceiver = "Receiver"
ResultMajorCodeRepresent = "Represent"
ResultMajorCodePending = "Pending"

ResultMinorCodeNoMatch = "NoMatch"
ResultMinorCodeTooManyResponses = "TooManyResponses"
ResultMinorCodeIncomplete = "Incomplete"
ResultMinorCodeFailure = "Failure"
ResultMinorCodeRefused = "Refused"
ResultMinorCodeNoAuthentication = "NoAuthentication"
ResultMinorCodeMessageNotSupported = "MessageNotSupported"
ResultMinorCodeUnknownResponseId = "UnknownResponseId"
ResultMinorCodeNotSynchronous = "NotSynchronous"

XkmsSoapSubcodeValueMessageNotSupported = "MessageNotSupported"
XkmsSoapSubcodeValueBadMessage = "BadMessage"

XkmsSoapFaultReasonLang = "en"
XkmsSoapFaultReasonUnsupportedVersion = "Unsupported SOAP version"
XkmsSoapFaultReasonUnableToProcess = "Unable to process %s"
XkmsSoapFaultReasonServiceUnavailable = "Service temporarily unable"
XkmsSoapFaultReasonMessageNotSupported = "%s message not supported"
XkmsSoapFaultReasonMessageInvalid = "%s message invalid"

XkmsFormatStrPlain = "plain"
XkmsFormatStrSoap11 = "soap-1.1"
XkmsFormatStrSoap12 = "soap-1.2"


# *************************************************************************
# *
# * KeyInfo Nodes
# *
# ************************************************************************/
NodeKeyInfo = "KeyInfo"
NodeReference = "Reference"
NodeTransforms = "Transforms"
NodeTransform = "Transform"

# *************************************************************************
# *
# * Attributes
# *
# ************************************************************************/
AttrId = "Id"
AttrURI = "URI"
AttrType = "Type"
AttrMimeType = "MimeType"
AttrEncoding = "Encoding"
AttrAlgorithm = "Algorithm"
AttrFilter = "Filter"
AttrRecipient = "Recipient"
AttrTarget = "Target"

# *************************************************************************
# *
# * AES strings
# *
# ************************************************************************/
NameAESKeyValue = "aes"
NodeAESKeyValue = "AESKeyValue"
HrefAESKeyValue = "http://www.aleksey.com/xmlsec/2002#AESKeyValue"

NameAes128Cbc = "aes128-cbc"
HrefAes128Cbc = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"

NameAes192Cbc = "aes192-cbc"
HrefAes192Cbc = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"

NameAes256Cbc = "aes256-cbc"
HrefAes256Cbc = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"

NameKWAes128 = "kw-aes128"
HrefKWAes128 = "http://www.w3.org/2001/04/xmlenc#kw-aes128"

NameKWAes192 = "kw-aes192"
HrefKWAes192 = "http://www.w3.org/2001/04/xmlenc#kw-aes192"

NameKWAes256 = "kw-aes256"
HrefKWAes256 = "http://www.w3.org/2001/04/xmlenc#kw-aes256"

# *************************************************************************
# *
# * BASE64 strings
# *
# ************************************************************************/
NameBase64 = "base64"
HrefBase64 = "http://www.w3.org/2000/09/xmldsig#base64"

# *************************************************************************
# *
# * C14N strings
# *
# ************************************************************************/
NameC14N = "c14n"
HrefC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

NameC14NWithComments = "c14n-with-comments"
HrefC14NWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"

NameExcC14N = "exc-c14n"
HrefExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"

NameExcC14NWithComments = "exc-c14n-with-comments"
HrefExcC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

NsExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
NsExcC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

NodeInclusiveNamespaces = "InclusiveNamespaces"
AttrPrefixList = "PrefixList"
# *************************************************************************
# *
# * DES strings
# *
# ************************************************************************/
NameDESKeyValue = "des"
NodeDESKeyValue = "DESKeyValue"
HrefDESKeyValue = "http://www.aleksey.com/xmlsec/2002#DESKeyValue"

NameDes3Cbc = "tripledes-cbc"
HrefDes3Cbc = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"

NameKWDes3 = "kw-tripledes"
HrefKWDes3 = "http://www.w3.org/2001/04/xmlenc#kw-tripledes"

# *************************************************************************
# *
# * DSA strings
# *
# ************************************************************************/
NameDSAKeyValue = "dsa"
NodeDSAKeyValue = "DSAKeyValue"
HrefDSAKeyValue = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue"
NodeDSAP = "P"
NodeDSAQ = "Q"
NodeDSAG = "G"
NodeDSAJ = "J"
NodeDSAX = "X"
NodeDSAY = "Y"
NodeDSASeed = "Seed"
NodeDSAPgenCounter = "PgenCounter"

NameDsaSha1 = "dsa-sha1"
HrefDsaSha1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"

# *************************************************************************
# *
# * EncryptedKey
# *
# ************************************************************************/
NameEncryptedKey = "enc-key"
NodeEncryptedKey = "EncryptedKey"
HrefEncryptedKey = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"

# *************************************************************************
# *
# * Enveloped transform strings
# *
# ************************************************************************/
NameEnveloped = "enveloped-signature"
HrefEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

# *************************************************************************
# *
# * HMAC strings
# *
# ************************************************************************/
NameHMACKeyValue = "hmac"
NodeHMACKeyValue = "HMACKeyValue"
HrefHMACKeyValue = "http://www.aleksey.com/xmlsec/2002#HMACKeyValue"

NodeHMACOutputLength = "HMACOutputLength"

NameHmacMd5 = "hmac-md5"
HrefHmacMd5 = "http://www.w3.org/2001/04/xmldsig-more#hmac-md5"

NameHmacRipemd160 = "hmac-ripemd160"
HrefHmacRipemd160 = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160"

NameHmacSha1 = "hmac-sha1"
HrefHmacSha1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"

NameHmacSha224 = "hmac-sha224"
HrefHmacSha224 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"

NameHmacSha256 = "hmac-sha256"
HrefHmacSha256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"

NameHmacSha384 = "hmac-sha384"
HrefHmacSha384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"

NameHmacSha512 = "hmac-sha512"
HrefHmacSha512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"

# *************************************************************************
# *
# * KeyName strings
# *
# ************************************************************************/
NameKeyName = "key-name"
NodeKeyName = "KeyName"

# *************************************************************************
# *
# * KeyValue strings
# *
# ************************************************************************/
NameKeyValue = "key-value"
NodeKeyValue = "KeyValue"

# *************************************************************************
# *
# * Memory Buffer strings
# *
# ************************************************************************/
NameMemBuf = "membuf-transform"

# *************************************************************************
# *
# * MD5 strings
# *
# ************************************************************************/
NameMd5 = "md5"
HrefMd5 = "http://www.w3.org/2001/04/xmldsig-more#md5"

# *************************************************************************
# *
# * RetrievalMethod
# *
# ************************************************************************/
NameRetrievalMethod = "retrieval-method"
NodeRetrievalMethod = "RetrievalMethod"

# *************************************************************************
# *
# * RIPEMD160 strings
# *
# ************************************************************************/
NameRipemd160 = "ripemd160"
HrefRipemd160 = "http://www.w3.org/2001/04/xmlenc#ripemd160"

# *************************************************************************
# *
# * RSA strings
# *
# ************************************************************************/
NameRSAKeyValue = "rsa"
NodeRSAKeyValue = "RSAKeyValue"
HrefRSAKeyValue = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue"
NodeRSAModulus = "Modulus"
NodeRSAExponent = "Exponent"
NodeRSAPrivateExponent = "PrivateExponent"

NameRsaMd5 = "rsa-md5"
HrefRsaMd5 = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"

NameRsaRipemd160 = "rsa-ripemd160"
HrefRsaRipemd160 = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160"

NameRsaSha1 = "rsa-sha1"
HrefRsaSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

NameRsaSha224 = "rsa-sha224"
HrefRsaSha224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"

NameRsaSha256 = "rsa-sha256"
HrefRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

NameRsaSha384 = "rsa-sha384"
HrefRsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"

NameRsaSha512 = "rsa-sha512"
HrefRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

NameRsaPkcs1 = "rsa-1_5"
HrefRsaPkcs1 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"

NameRsaOaep = "rsa-oaep-mgf1p"
HrefRsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
NodeRsaOAEPparams = "OAEPparams"

# *************************************************************************
# *
# * SHA1 strings
# *
# ************************************************************************/
NameSha1 = "sha1"
HrefSha1 = "http://www.w3.org/2000/09/xmldsig#sha1"

NameSha224 = "sha224"
HrefSha224 = "http://www.w3.org/2001/04/xmldsig-more#sha224"

NameSha256 = "sha256"
HrefSha256 = "http://www.w3.org/2001/04/xmlenc#sha256"

NameSha384 = "sha384"
HrefSha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"

NameSha512 = "sha512"
HrefSha512 = "http://www.w3.org/2001/04/xmlenc#sha512"

# *************************************************************************
# *
# * X509 strings
# *
# ************************************************************************/
NameX509Data = "x509"
NodeX509Data = "X509Data"
HrefX509Data = "http://www.w3.org/2000/09/xmldsig#X509Data"

NodeX509Certificate = "X509Certificate"
NodeX509CRL = "X509CRL"
NodeX509SubjectName = "X509SubjectName"
NodeX509IssuerSerial = "X509IssuerSerial"
NodeX509IssuerName = "X509IssuerName"
NodeX509SerialNumber = "X509SerialNumber"
NodeX509SKI = "X509SKI"

NameRawX509Cert = "raw-x509-cert"
HrefRawX509Cert = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate"

NameX509Store = "x509-store"

# *************************************************************************
# *
# * PGP strings
# *
# ************************************************************************/
NamePGPData = "pgp"
NodePGPData = "PGPData"
HrefPGPData = "http://www.w3.org/2000/09/xmldsig#PGPData"

# *************************************************************************
# *
# * SPKI strings
# *
# ************************************************************************/
NameSPKIData = "spki"
NodeSPKIData = "SPKIData"
HrefSPKIData = "http://www.w3.org/2000/09/xmldsig#SPKIData"

# *************************************************************************
# *
# * XPath/XPointer strings
# *
# ************************************************************************/
NameXPath = "xpath"
NodeXPath = "XPath"

NameXPath2 = "xpath2"
NodeXPath2 = "XPath"
XPath2FilterIntersect = "intersect"
XPath2FilterSubtract = "subtract"
XPath2FilterUnion = "union"

NameXPointer = "xpointer"
NodeXPointer = "XPointer"

# *************************************************************************
# *
# * Xslt strings
# *
# ************************************************************************/
NameXslt = "xslt"
HrefXslt = "http://www.w3.org/TR/1999/REC-xslt-19991116"

# *************************************************************************
# *
# * SOAP 1.1/1.2 strings
# *
# ************************************************************************/
NodeEnvelope = "Envelope"
NodeHeader = "Header"
NodeBody = "Body"
NodeFault = "Fault"
NodeFaultCode = "faultcode"
NodeFaultString = "faultstring"
NodeFaultActor = "faultactor"
NodeFaultDetail = "detail"
NodeCode = "Code"
NodeReason = "Reason"
NodeNode = "Node"
NodeRole = "Role"
NodeDetail = "Detail"
NodeValue = "Value"
NodeSubcode = "Subcode"
NodeText = "Text"


SoapFaultCodeVersionMismatch = "VersionMismatch"
SoapFaultCodeMustUnderstand = "MustUnderstand"
SoapFaultCodeClient = "Client"
SoapFaultCodeServer = "Server"
SoapFaultCodeReceiver = "Receiver"
SoapFaultCodeSender = "Sender"
SoapFaultDataEncodningUnknown = "DataEncodingUnknown"



# *************************************************************************
# *
# * Utility strings
# *
# ************************************************************************/
StringEmpty = ""
StringCR = "\n"






