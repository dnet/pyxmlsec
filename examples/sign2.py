#!/usr/bin/env python2.2

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

doc = libxml2.parseFile("./sign2-doc.xml")
#signNode = xmlsec.tmplSignatureCreate(doc, xmlsec.transformExclC14NId,
#                                      xmlsec.transformRsaSha1Id, None)
signNode = xmlsec.TmplSignature(doc, xmlsec.transformExclC14NId,
                                xmlsec.transformRsaSha1Id, None)
doc.getRootElement().addChild(signNode)

refNode = signNode.addReference(xmlsec.transformSha1Id, None, None, None)
refNode.addTransform(xmlsec.transformEnvelopedId)

keyInfoNode = signNode.ensureKeyInfo(None);
keyNameInfo = keyInfoNode.addKeyName(None)

dsig_ctx = xmlsec.DSigCtx()
key = xmlsec.cryptoAppKeyLoad("./rsakey.pem", xmlsec.KeyDataFormatPem,
                              None, None, None)

key.setName("./rsakey.pem")

dsig_ctx.setSignKey(key)

dsig_ctx.sign(signNode)
doc.dump("-")

dsig_ctx.destroy()
doc.freeDoc()

xmlsec.cryptoShutdown()
xmlsec.cryptoAppShutdown()

xmlsec.shutdown()

libxml2.cleanupParser()
