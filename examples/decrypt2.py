#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Decrypting an encrypted file using keys manager.
#
# Decrypts encrypted XML file using keys manager and a list of 
# DES key from a binary file
#
# Usage: 
#	decrypt2.py <xml-enc> <des-key-file1> [<des-key-file2> [...]] 
#
# Example:
#	./decrypt2.py encrypt1-res.xml deskey.bin
#	./decrypt2.py encrypt2-res.xml deskey.bin
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2003-2004 Valery Febvre <vfebvre@easter-eggs.com>
#

import os, sys
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

    # Create keys manager and load keys
    mngr = load_des_keys(sys.argv[2:], len(sys.argv) - 2)

    if mngr is not None:
        res = decrypt_file(mngr, sys.argv[1])
        # Destroy keys manager
        mngr.destroy()

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Creates simple keys manager and load DES keys from files in it.
# The caller is responsible for destroying returned keys manager using
# destroy.
#
# Returns the newly created keys manager or None if an error occurs.
def load_des_keys(files, files_size):
    assert(files)
    assert(files_size > 0)

    # Create and initialize keys manager, we use a simple list based
    # keys manager, implement your own KeysStore klass if you need
    # something more sophisticated
    mngr = xmlsec.KeysMngr()
    if mngr is None:
        print "Error: failed to create keys manager."
        return None
    if xmlsec.cryptoAppDefaultKeysMngrInit(mngr) < 0:
        print "Error: failed to initialize keys manager."
        mngr.destroy()
        return None
    for file in files:
        if not check_filename(file):
            mngr.destroy()
            return None
        # Load DES key
        key = xmlsec.keyReadBinaryFile(xmlsec.keyDataDesId(), file)
        if key is None:
    	    print "Error: failed to load des key from binary file \"%s\"" % file
	    mngr.destroy()
            return None
        # Add key to keys manager, from now on keys manager is responsible
	# for destroying key
        if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(mngr, key) < 0:
    	    print "Error: failed to add key from \"%s\" to keys manager" % file
            key.destroy()
	    mngr.destroy()
            return None
    return mngr


# Decrypts the XML file enc_file using DES key files in mngr and 
# prints results to stdout.
#
# Returns 0 on success or a negative value if an error occurs.
def decrypt_file(mngr, enc_file):
    assert(mngr)
    assert(enc_file)

    # Load template
    if not check_filename(enc_file):
        return -1
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

    # Create encryption context
    enc_ctx = xmlsec.EncCtx(mngr)
    if enc_ctx is None:
        print "Error: failed to create encryption context"
        return cleanup(doc)

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


def check_filename(filename):
    if os.access(filename, os.R_OK):
        return 1
    else:
        print "Error: XML file \"%s\" not found OR no read access" % filename
        return 0


if __name__ == "__main__":
    main()
