#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Decrypting an encrypted file using a single key.

# Decrypts encrypted XML file using a single DES key from a binary file
#
# Usage: 
#	./decrypt1.py <xml-enc> <des-key-file> 
#
# Example:
#	./decrypt1.py encrypt1-res.xml deskey.bin
#	./decrypt1.py encrypt2-res.xml deskey.bin
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2003-2004 Valery Febvre <vfebvre@easter-eggs.com>
#

import sys
sys.path.insert(0, '../')

import libxml2
import xmlsec

def main():
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

    res = decrypt_file(sys.argv[1], sys.argv[2])

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Decrypts the XML file enc_file using DES key from key_file and
# prints results to stdout.
# Returns 0 on success or a negative value if an error occurs.
def decrypt_file(enc_file, key_file):
    assert(enc_file)
    assert(key_file)

    # Load template
    doc = libxml2.parseFile(enc_file)
    if doc is None or doc.getRootElement() is None:
	print "Error: unable to parse file \"%s\"" % enc_file
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
        
    # Load DES key
    key = xmlsec.keyReadBinaryFile(xmlsec.keyDataDesId(), key_file)
    if key is None:
        print "Error failed to load DES key from binary file \"%s\"" % key_file
        return cleanup(doc, enc_ctx)

    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        return cleanup(doc, enc_ctx)

    enc_ctx.encKey = key

    # Decrypt the data
    if enc_ctx.decrypt(node) < 0 or enc_ctx.result is None:
        print "Error: decryption failed"
        return cleanup(doc, enc_ctx)

    # Print decrypted data to stdout
    if enc_ctx.resultReplaced != 0:
        print "Decrypted XML data:"
        doc.dump("-")
    else:
        print "Decrypted binary data (%d bytes):" % enc_ctx.result.getSize()
        print enc_ctx.result.getData()

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
