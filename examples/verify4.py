#!/usr/bin/env python
#
# $Id$
#
# PyXMLSec example: Verifying a simple SAML response with X509 certificate
#
# Verifies a simple SAML response. In addition to refular verification
# we ensure that the signature has only one <dsig:Reference/> element
# with an empty or NULL URI attribute and one enveloped signature transform
# as it is required by SAML specification.
#
# This example was developed and tested with OpenSSL crypto library. The 
# certificates management policies for another crypto library may break it.
#
# Usage: 
#	verify4.py <signed-file> <trusted-cert-pem-file1> [<trusted-cert-pem-file2> [...]]
#
# Example (success):
#	./verify4.py verify4-res.xml rootcert.pem
#
# Example (failure):
#	./verify4.py verify4-bad-res.xml rootcert.pem
# In the same time, verify3 example successfuly verifies this signature:
#	./verify3.py verify4-bad-res.xml rootcert.pem
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
# 
# Copyright (C) 2003-2013 Valery Febvre <vfebvre@easter-eggs.com>
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

    # Create keys manager and load trusted certificates
    mngr = load_trusted_certs(sys.argv[2:], len(sys.argv) - 2)

    # Verify file
    if mngr is not None:
        res = verify_file(mngr, sys.argv[1])
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


# Creates simple keys manager and load trusted certificates from PEM files.
# The caller is responsible for destroying returned keys manager using
# destroy method.
#
# Returns the newly created keys manager or None if an error occurs.
def load_trusted_certs(files, files_size):
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
        # Load trusted cert
        if mngr.certLoad(file, xmlsec.KeyDataFormatPem,
                         xmlsec.KeyDataTypeTrusted) < 0:
            print "Error: failed to load pem certificate from \"%s\"", file
            mngr.destroy()
            return None
    return mngr


# Verifies XML signature in xml_file.
# Returns 0 on success or a negative value if an error occurs.
def verify_file(mngr, xml_file):
    assert(mngr)
    assert(xml_file)

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
    if node is None:
        print "Error: start node not found in \"%s\"", xml_file

    # Create signature context
    dsig_ctx = xmlsec.DSigCtx(mngr)
    if dsig_ctx is None:
        print "Error: failed to create signature context"
        return cleanup(doc)

    # Limit the Reference URI attributes to empty or None
    dsig_ctx.enabledReferenceUris = xmlsec.TransformUriTypeEmpty

    # Limit allowed transforms for signature and reference processing
    if (dsig_ctx.enableSignatureTransform(xmlsec.transformInclC14NId()) < 0 or
        dsig_ctx.enableSignatureTransform(xmlsec.transformExclC14NId()) < 0 or
        dsig_ctx.enableSignatureTransform(xmlsec.transformSha1Id())     < 0 or
        dsig_ctx.enableSignatureTransform(xmlsec.transformRsaSha1Id())  < 0):
        print "Error: failed to limit allowed signature transforms"
        return cleanup(doc, dsig_ctx)
    if (dsig_ctx.enableReferenceTransform(xmlsec.transformInclC14NId()) < 0 or
        dsig_ctx.enableReferenceTransform(xmlsec.transformExclC14NId()) < 0 or
        dsig_ctx.enableReferenceTransform(xmlsec.transformSha1Id())     < 0 or
        dsig_ctx.enableReferenceTransform(xmlsec.transformEnvelopedId())< 0):
        print "Error: failed to limit allowed reference transforms"
        return cleanup(doc, dsig_ctx)

    # In addition, limit possible key data to valid X509 certificates only
    if dsig_ctx.keyInfoReadCtx.enabledKeyData.add(xmlsec.keyDataX509Id()) < 0:
        print "Error: failed to limit allowed key data"
        return cleanup(doc, dsig_ctx)

    # Verify signature
    if dsig_ctx.verify(node) < 0:
        print "Error: signature verify"
        return cleanup(doc, dsig_ctx)

    # Check that we have only one Reference
    if (dsig_ctx.status == xmlsec.DSigStatusSucceeded and
        dsig_ctx.signedInfoReferences.getSize() != 1):
        print "Error: only one reference is allowed"
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
