#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Encrypting XML file with a dynamicaly created template.
#
# Encrypts XML file using a dynamicaly created template file and a DES key 
# from a binary file
#
# Usage: 
#	./encrypt2.py <xml-doc> <des-key-file> 
#
# Example:
#	./encrypt2.py encrypt2-doc.xml deskey.bin > encrypt2-res.xml
#
# The result could be decrypted with decrypt1 example:
#	./decrypt1.py encrypt2-res.xml deskey.bin
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
        print "Usage: %s <xml-tmpl> <key-file>" % sys.argv[0]
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

    res = encrypt_file(sys.argv[1], sys.argv[2])

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Encrypts xml_file using a dynamicaly created template and DES key from
# key_file.
# Returns 0 on success or a negative value if an error occurs.
def encrypt_file(xml_file, key_file):
    assert(xml_file)
    assert(key_file)

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

    # add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the
    # signed document
    key_info_node = enc_data_node.ensureKeyInfo(None)
    if key_info_node is None:
	print "Error: failed to add key info"
        cleanup(doc, enc_data_node)

    if key_info_node.addKeyName(None) is None:
	print "Error: failed to add key name"
        cleanup(doc, enc_data_node)

    # Create encryption context, we don't need keys manager in this example
    enc_ctx = xmlsec.EncCtx(None)
    if enc_ctx is None:
        print "Error: failed to create encryption context"
        cleanup(doc, enc_data_node)

    # Load DES key, assuming that there is not password
    if not check_filename(key_file):
        cleanup(doc, enc_data_node, enc_ctx)
    key = xmlsec.keyReadBinaryFile(xmlsec.keyDataDesId(), key_file)
    if key is None:
        print "Error failed to load DES key from binary file \"%s\"" % key_file
        return cleanup(doc, enc_data_node, enc_ctx)

    # Set key name to the file name, this is just an example!
    if key.setName(key_file) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        return cleanup(doc, enc_data_node, enc_ctx)

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
