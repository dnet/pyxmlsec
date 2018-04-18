#! /usr/bin/env python
#
# $Id$ 
# 
# PyXMLSec - Python bindings for XML Security library (XMLSec)
# Automatic generation of xmlsec_strings.py with src/strings.c
#
# Copyright (C) 2003-2013 Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
# 
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.

import re, sys

MATCH_BLANK   = re.compile(r'^\s*\n$')
MATCH_COMMENT = re.compile(r'^[ /]+(?P<text>.*)\n$')
MATCH_CONST   = re.compile(r'^const\s+xmlChar\s+(?P<name>\w+)\[\]\s*=\s+(?P<value>.*)\n$')

header = """# $%s$
# 
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2013 Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
# 
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This is free software; see COPYING file in the source
# distribution for preciese wording.
#
""" % "Id"

file_in = sys.argv[1]
file_out = "./xmlsec_strings.py"

fd_in  = open(file_in,  "r")
fd_out = open(file_out, "w+")
fd_out.write(header)

line  = fd_in.readline()
while line:
    match = MATCH_CONST.search(line)
    if match:
        fd_out.write("%s = %s\n" % (match.group('name')[6:],
                                    match.group('value')[:-1]))
    else:
        match = MATCH_COMMENT.search(line)
        if match:
            fd_out.write("# %s\n" % match.group('text'))
        else:
            match = MATCH_BLANK.search(line)
            if match:
                fd_out.write("\n")
            else:
                print "Unknown format, this line is ignored: %s" % line
    line  = fd_in.readline()

fd_in.close()
fd_out.close()
