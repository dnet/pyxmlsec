#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Verifying a file using a single key.
#
# Verifies a file using a key from PEM file.
#
# Usage: 
#	./verify1.py <signed-file> <pem-key> 
#
# Example:
#	./verify1.py sign1-res.xml rsapub.pem
#	./verify1.py sign2-res.xml rsapub.pem
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
    if len(sys.argv) < 3:
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

    res = verify_file(sys.argv[1], sys.argv[2])

    # Shutdown xmlsec-crypto library
    xmlsec.cryptoShutdown()

    # Shutdown crypto library
    xmlsec.cryptoAppShutdown()

    # Shutdown xmlsec library
    xmlsec.shutdown()

    # Shutdown LibXML2
    libxml2.cleanupParser()

    sys.exit(res)


# Verifies XML signature in xml_file using public key from key_file.
# Returns 0 on success or a negative value if an error occurs.
def verify_file(xml_file, key_file):
    assert(xml_file)
    assert(key_file)

    # Load XML file
    if not check_filename(xml_file):
        return -1
    doc = libxml2.parseFile(xml_file)
    if doc is None or doc.getRootElement() is None:
	print "Error: unable to parse file \"%s\"" % tmpl_file
        return cleanup(doc)

    # Find start node
    node = xmlsec.findNode(doc.getRootElement(),
                           xmlsec.NodeSignature, xmlsec.DSigNs)

    # Create signature context, we don't need keys manager in this example
    dsig_ctx = xmlsec.DSigCtx()
    if dsig_ctx is None:
        print "Error: failed to create signature context"
        return cleanup(doc)

    # Load private key, assuming that there is not password
    key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                  None, None, None)
    if key is None:
        print "Error: failed to load private pem key from \"%s\"" % key_file
        return cleanup(doc, dsig_ctx)
    dsig_ctx.signKey = key

    # Set key name to the file name, this is just an example!
    if not check_filename(key_file):
        return cleanup(doc, dsig_ctx)
    if key.setName(key_file) < 0:
        print "Error: failed to set key name for key from \"%s\"" % key_file
        return cleanup(doc, dsig_ctx)

    # Verify signature
    if dsig_ctx.verify(node) < 0:
        print "Error: signature verify"
        return cleanup(doc, dsig_ctx)

    # Print verification result to stdout
    if dsig_ctx.status == xmlsec.DSigStatusSucceeded:
        print "Signature is OK"
    else:
        print "Signature is INVALID"

    # Success
    return cleanup(doc, dsig_ctx, 1)


def cleanup(doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
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
