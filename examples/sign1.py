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

doc = libxml2.parseFile("./sign1-tmpl.xml")
node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, xmlsec.DSigNs)
dsig_ctx = xmlsec.dsigCtxCreate()
key = xmlsec.cryptoAppKeyLoad("./rsakey.pem", 2, "", None, None)
dsig_ctx.setSignKey(key)
dsig_ctx.sign(node)
doc.dump("-")

xmlsec.cryptoShutdown()
xmlsec.cryptoAppShutdown()

xmlsec.shutdown()

libxml2.cleanupParser()
