#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Encrypting XML file with a session key and dynamicaly
# created template.
#
# Encrypts XML file using a dynamicaly created template file and a session 
# DES key (encrypted with an RSA key).
#
# Usage: 
#	./encrypt3.py <xml-doc> <rsa-pem-key-file> 
#
# Example:
#	./encrypt3.py encrypt3-doc.xml rsakey.pem > encrypt3-res.xml
#
# The result could be decrypted with decrypt3 example:
#	./decrypt3.py encrypt3-res.xml
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2003-2004 Valery Febvre <vfebvre@easter-eggs.com>
#

import sys, os
sys.path.insert(0, '../')

import libxml2
import xmlsec

def main():
    assert(sys.argv)
    if len(sys.argv) != 3:
        print "Error: wrong number of arguments."
        print "Usage: %s <xml-file> <key-file>" % sys.argv[0]
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
    mngr = load_rsa_keys(sys.argv[2])

    # We use key filename as key name here
    if mngr is not None:
        res = encrypt_file(mngr, sys.argv[1], sys.argv[2])
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


# Creates simple keys manager and load RSA key from key_file in it.
# The caller is responsible for destroying returned keys manager using destroy.
#
# Returns the newly created keys manager or None if an error occurs.
def load_rsa_keys(key_file):
    assert(key_file)

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
    # Load private RSA key
    if not check_filename(key_file):
        mngr.destroy()
        return None
    key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                  None, None, None);
    if key is None:
        print "Error: failed to load rsa key from file \"%s\"" % key_file
        mngr.destroy()
        return None
    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        key.destroy()
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


# Encrypts xml_file using a dynamicaly created template, a session DES key 
# and an RSA key from keys manager.
# Returns 0 on success or a negative value if an error occurs.
def encrypt_file(mngr, xml_file, key_name):
    assert(mngr)
    assert(xml_file)
    assert(key_name)

    # Load template
    if not check_filename(xml_file):
        return -1
    doc = libxml2.parseFile(xml_file)
    if doc is None or doc.getRootElement() is None:
	print "Error: unable to parse file \"%s\"" % xml_file
        return cleanup(doc)

    # Create encryption template to encrypt XML file and replace 
    # its content with encryption result
    enc_data_node = xmlsec.TmplEncData(doc, xmlsec.transformDes3CbcId(),
                                       None, xmlsec.TypeEncElement, None, None)
    if enc_data_node is None:
	print "Error: failed to create encryption template"
        cleanup(doc)

    # We want to put encrypted data in the <enc:CipherValue/> node
    if enc_data_node.ensureCipherValue() is None:
	print "Error: failed to add CipherValue node"
        cleanup(doc, enc_data_node)

    # add <dsig:KeyInfo/>
    key_info_node = enc_data_node.ensureKeyInfo(None)
    if key_info_node is None:
	print "Error: failed to add key info"
        cleanup(doc, enc_data_node)

    # Add <enc:EncryptedKey/> to store the encrypted session key
    enc_key_node = key_info_node.addEncryptedKey(xmlsec.transformRsaOaepId(), 
                                               None, None, None)
    if enc_key_node is None:
	print "Error: failed to add key info"
        cleanup(doc, enc_data_node)

    # We want to put encrypted key in the <enc:CipherValue/> node
    if enc_key_node.ensureCipherValue() is None:
	print "Error: failed to add CipherValue node"
        cleanup(doc, enc_data_node)

    # Add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to <enc:EncryptedKey/>
    key_info_node2 = enc_key_node.ensureKeyInfo(None)
    if key_info_node2 is None:
	print "Error: failed to add key info"
        cleanup(doc, enc_data_node)
    
    # Set key name so we can lookup key when needed
    if key_info_node2.addKeyName(key_name) is None:
	print "Error: failed to add key name"
        cleanup(doc, enc_data_node)

    # Create encryption context
    enc_ctx = xmlsec.EncCtx(mngr)
    if enc_ctx is None:
        print "Error: failed to create encryption context"
        cleanup(doc, enc_data_node)

    # Generate a Triple DES key
    key = xmlsec.keyGenerate(xmlsec.keyDataDesId(), 192,
                             xmlsec.KeyDataTypeSession)
    if key is None:
        print "Error: failed to generate session DES key"
        cleanup(doc, enc_data_node)

    enc_ctx.encKey = key

    # Encrypt the data
    if enc_ctx.xmlEncrypt(enc_data_node, doc.getRootElement()) < 0:
        print "Error: encryption failed"
        return cleanup(doc, enc_data_node, enc_ctx)

    doc.dump("-")

    # Success
    return cleanup(doc, None, enc_ctx, 1)


def cleanup(doc=None, enc_data_node=None, enc_ctx=None, res=-1):
    if enc_ctx is not None:
        enc_ctx.destroy()
    if enc_data_node is not None:
         enc_data_node.freeNode()
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
