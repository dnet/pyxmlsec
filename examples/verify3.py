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

#############################

mngr = xmlsec.KeysMngr()
xmlsec.cryptoAppDefaultKeysMngrInit(mngr)
xmlsec.cryptoAppKeysMngrCertLoad(mngr, "./rootcert.pem",
                                 xmlsec.KeyDataFormatPem,
                                 xmlsec.KeyDataTypeTrusted)
doc = libxml2.parseFile("./sign3-res.xml")
node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, xmlsec.DSigNs)
dsig_ctx = xmlsec.DSigCtx(mngr)
if dsig_ctx.verify(node) < 0:
    print "Error: signature verify"
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
