#!/usr/bin/env python

import sys
sys.path.insert(0, '../')

import libxml2
import libxslt

import xmlsec

libxml2.initParser()
libxml2.substituteEntitiesDefault(1)

xmlsec.init()

xmlsec.cryptoAppInit(None)
xmlsec.cryptoInit()

#############################

mngr = xmlsec.keysMngrCreate()
xmlsec.cryptoAppDefaultKeysMngrInit(mngr)
xmlsec.cryptoAppKeysMngrCertLoad(mngr, "./rootcert.pem",
                                 xmlsec.KeyDataFormatPem,
                                 xmlsec.KeyDataTypeTrusted)

doc = libxml2.parseFile("./verify4-res.xml")
node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, xmlsec.DSigNs)
dsig_ctx = xmlsec.dsigCtxCreate(mngr)

dsig_ctx.setEnabledReferenceUris(xmlsec.TransformUriTypeEmpty)
if (dsig_ctx.enableSignatureTransform(xmlsec.transformInclC14NId) < 0 or
    dsig_ctx.enableSignatureTransform(xmlsec.transformExclC14NId) < 0 or
    dsig_ctx.enableSignatureTransform(xmlsec.transformSha1Id)     < 0 or
    dsig_ctx.enableSignatureTransform(xmlsec.transformRsaSha1Id)  < 0):
    print "Error: failed to limit allowed siganture transforms"

if (dsig_ctx.enableReferenceTransform(xmlsec.transformInclC14NId) < 0 or
    dsig_ctx.enableReferenceTransform(xmlsec.transformExclC14NId) < 0 or
    dsig_ctx.enableReferenceTransform(xmlsec.transformSha1Id)     < 0 or
    dsig_ctx.enableReferenceTransform(xmlsec.transformEnvelopedId)< 0):
    print "Error: failed to limit allowed reference transforms"

enable_key_data = dsig_ctx.getKeyInfoReadCtx().getEnabledKeyData()
enable_key_data.add(xmlsec.keyDataX509Id)

if dsig_ctx.verify(node) < 0:
    print "Error: signature verify"

if dsig_ctx.getSignedInfoReferences().getSize() != 1:
    print "Error: only one reference is allowed"

if dsig_ctx.getStatus():
    print "Signature is OK"
else:
    print "Signature is INVALID"

mngr.destroy()
dsig_ctx.destroy()
doc.freeDoc()

##############################

xmlsec.cryptoShutdown()
xmlsec.cryptoAppShutdown()

xmlsec.shutdown()

libxml2.cleanupParser()
