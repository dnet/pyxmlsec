#!/usr/bin/env python2.2

import sys
sys.path.insert(0, '../')

import libxml2
import libxslt

import xmlsec

def load_keys(pem_file):
    mngr = xmlsec.KeysMngr()
    if xmlsec.cryptoAppDefaultKeysMngrInit(mngr) < 0:
        print "Error: failed to initialize keys manager"
        mngr.destroy()
        return None
    key = xmlsec.cryptoAppKeyLoad(pem_file, xmlsec.KeyDataFormatPem, None, None, None)
    if key == None:
        print "Error: failed to load pem key from " + pem_file
        mngr.destroy()        
        return None
    if key.setName(pem_file) < 0:
        print "Error: failed to set key name for key from " + pem_file
        key.destroy()
        mngr.destroy()
        return None
    if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(mngr, key) < 0:
        print "Error: failed to add key from \"%s\" to keys manager" % pem_file
        key.destroy()
        mngr.destroy()
        return None
    return mngr

libxml2.initParser()
libxml2.substituteEntitiesDefault(1)

xmlsec.init()

xmlsec.cryptoAppInit(None)
xmlsec.cryptoInit()

#############################

mngr = load_keys("./rsapub.pem")

doc = libxml2.parseFile("./sign1-res.xml")
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
