#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Decrypting an encrypted file using a custom keys manager.
#
# Decrypts encrypted XML file using a custom files based keys manager.
# We assume that key's name in <dsig:KeyName/> element is just 
# key's file name in the current folder.
# 
# Usage:
#	./decrypt3.py <xml-enc> 
#
# Example:
#	./decrypt3.py encrypt1-res.xml
#	./decrypt3.py encrypt2-res.xml
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
    if len(sys.argv) != 2:
        print "Error: wrong number of arguments."
        print "Usage: %s <enc-file>" % sys.argv[0]
        return sys.exit(1)
    
    res = 0
    # Init libxml library
    libxml2.initParser()
    libxml2.substituteEntitiesDefault(1)

    # Init xmlsec library
    if xmlsec.init() < 0:
        print "Error: xmlsec initialization failed."
        return sys.exit(-1)
    
    # Check loaded library version
    if xmlsec.checkVersion() != 1:
	print "Error: loaded xmlsec library version is not compatible."
	sys.exit(-1)

    # Init crypto library
    if xmlsec.cryptoAppInit(None) < 0:
        print "Error: crypto initialization failed."
    
    # Init xmlsec-crypto library
    if xmlsec.cryptoInit() < 0:
        print "Error: xmlsec-crypto initialization failed."

    # Create keys manager and load keys */
    mngr = create_files_keys_mngr()

    if mngr is not None:
        res = decrypt_file(mngr, sys.argv[1])

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Callback function
def getKeyCallback(keyInfoNode, keyInfoCtx):
    # Convert PyCObject object into xmlNode and KeyInfoCtx Objects
    node = libxml2.xmlNode(_obj=keyInfoNode)
    ctx = xmlsec.KeyInfoCtx(_obj=keyInfoCtx)
    return xmlsec.keysMngrGetKey(node, ctx)


# Creates a files based keys manager
# we assume that key name is the key file name
# Returns newly created keys manager or None if an error occurs.
def create_files_keys_mngr():
    # Create files based keys store
    storeId = xmlsec.KeyStoreId(0, 0, "files-based-keys-store",
                                None, None, files_keys_store_find_key)
    keysStore = xmlsec.KeyStore(storeId)

    if keysStore is None:
	print "Error: failed to create keys store."
	return None
    
    # Create keys manager
    mngr = xmlsec.KeysMngr()
    if mngr is None:
	print "Error: failed to create keys manager."
	keysStore.destroy()
	return None

    # Add store to keys manager, from now on keys manager destroys the store
    # if needed
    if mngr.adoptKeysStore(keysStore) < 0:
	print "Error: failed to add keys store to keys manager."
	keysStore.destroy()
	mngr.destroy()
	return None
    
    # Initialize crypto library specific data in keys manager
    if xmlsec.cryptoKeysMngrInit(mngr) < 0:
	print "Error: failed to initialize crypto data in keys manager."
	keysStore.destroy()
	mngr.destroy()
	return None

    # Set the get key callback
    mngr.getKey = getKeyCallback
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


# Lookups key in the store. The caller is responsible for destroying
# returned key with destroy method.
#
# Returns key or None if key not found or an error occurs.
def files_keys_store_find_key(store, name, keyInfoCtx):
    assert(store)
    assert(keyInfoCtx)
    
    ctx = xmlsec.KeyInfoCtx(_obj=keyInfoCtx)
    
    # It's possible to do not have the key name or desired key type 
    # but we could do nothing in this case
    if name is None or ctx.keyReq.keyId == xmlsec.KeyDataIdUnknown:
        print "Return None"
        return None
    
    if ctx.keyReq.keyId == xmlsec.keyDataDsaId() or ctx.keyReq.keyId == xmlsec.keyDataRsaId():
	# Load key from a pem file, if key is not found then it's an error (is it?)
	key = xmlsec.CryptoAppKeyLoad(name, xmlsec.KeyDataFormatPem, None, None, None)
        if key is None:
    	    print "Error: failed to load public pem key from \"%s\"" % name
	    return None
    else:
        # Otherwise it's a binary key, if key is not found then it's an error (is it?)
        key = xmlsec.keyReadBinaryFile(ctx.keyReq.keyId, name)
        if key is None:
            print "Error: failed to load key from binary file \"%s\"" % name
            return None
    
    # Set key name
    if key.setName(name) < 0:
        print "Error: failed to set key name for key from \"%s\"" % name
        key.destroy();
        return None
    
    return key


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
