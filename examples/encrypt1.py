#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Encrypting data using a template file.
#
# Encrypts binary data using a template file and a DES key from a binary file
#
# Usage: 
#	./encrypt1.py <xml-tmpl> <des-key-file> 
#
# Example:
#	./encrypt1.py encrypt1-tmpl.xml deskey.bin > encrypt1-res.xml
#
# The result could be decrypted with decrypt1 example:
#	./decrypt1.py encrypt1-res.xml deskey.bin
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
# Copyright (C) 2003 Valery Febvre <vfebvre@easter-eggs.com>
#

import sys
sys.path.insert(0, '../')

import libxml2
import xmlsec

def main():
    secret_data = "Big secret"

    assert(sys.argv)
    if len(sys.argv) < 3:
        print "Error: wrong number of arguments."
        print "Usage: %s <xml-tmpl> <des-key-file>" % sys.argv[0]
        return sys.exit(1)
    
    # Init libxml library
    libxml2.initParser()
    libxml2.substituteEntitiesDefault(1)

    # Init xmlsec library
    if xmlsec.init() < 0:
        print "Error: xmlsec initialization failed."
        return sys.exit(-1)
    
    # Check loaded library version
    if xmlsec.checkVersion() != 1:
	print "Error: loaded xmlsec library version is not compatible.\n"
	sys.exit(-1)

    # Init crypto library
    if xmlsec.cryptoAppInit(None) < 0:
        print "Error: crypto initialization failed."
    
    # Init xmlsec-crypto library
    if xmlsec.cryptoInit() < 0:
        print "Error: xmlsec-crypto initialization failed."

    res = encrypt_file(sys.argv[1], sys.argv[2], secret_data, len(secret_data))

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Encrypts binary #data using template from tmpl_file and DES key from key_file.
# Returns 0 on success or a negative value if an error occurs.
def encrypt_file(tmpl_file, key_file, data, dataSize):
    assert(tmpl_file)
    assert(key_file)
    assert(data)

    # Load template
    doc = libxml2.parseFile(tmpl_file)
    if doc is None or doc.getRootElement() is None:
	print "Error: unable to parse file \"%s\"" % tmpl_file
        return cleanup(doc)
    
    # Find start node
    node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeEncryptedData,
                           xmlsec.EncNs)
    if node is None:
	print "Error: start node not found in \"%s\"" % tmpl_file
        return cleanup(doc)

    # Create encryption context, we don't need keys manager in this example
    enc_ctx = xmlsec.EncCtx(None)
    if enc_ctx is None:
        print "Error: failed to create encryption context"
        return cleanup(doc)
        
    # Load DES key, assuming that there is not password
    key = xmlsec.keyReadBinaryFile(xmlsec.keyDataDesId, key_file)
    if key is None:
        print "Error failed to load DES key from binary file \"%s\"" % key_file
        return cleanup(doc, enc_ctx)

    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        return cleanup(doc, enc_ctx)

    enc_ctx.setEncKey(key)

    # Encrypt the data
    if enc_ctx.binaryEncrypt(node, data, dataSize) < 0:
        print "Error: encryption failed"
        return cleanup(doc, enc_ctx)

    doc.dump("-")

    # Success
    return cleanup(doc, enc_ctx, 1)


def cleanup(doc=None, enc_ctx=None, res=-1):
    if enc_ctx is not None:
        enc_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res


if __name__ == "__main__":
    main()
