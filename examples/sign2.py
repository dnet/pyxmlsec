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

doc = libxml2.parseFile("./sign2-doc.xml")
signNode = xmlsec.tmplSignatureCreate(doc, 1, 1, "")
doc.getRootElement().addChild(signNode)

refNode = signNode.addReference(1, "", "", "")
refNode.addTransform(1)

keyInfoNode = signNode.ensureKeyInfo(None);
keyNameInfo = keyInfoNode.addKeyName(None)

dsig_ctx = xmlsec.dsigCtxCreate()
key = xmlsec.cryptoAppKeyLoad("./rsakey.pem", 2, None, None, None)

key.setName("./rsakey.pem")

dsig_ctx.setSignKey(key)

dsig_ctx.sign(signNode)
doc.dump("-")

xmlsec.cryptoShutdown()
xmlsec.cryptoAppShutdown()

xmlsec.shutdown()

libxml2.cleanupParser()
