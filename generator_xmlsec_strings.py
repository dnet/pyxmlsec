#! /usr/bin/env python
#
# $Id$ 
# 
# PyXMLSec - Python bindings for XML Security library (XMLSec)
# Automatic generation of xmlsec_strings.py with src/strings.c
#
# Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
# to whom the Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.


import re, sys

MATCH_BLANK   = re.compile(r'^\s*\n$')
MATCH_COMMENT = re.compile(r'^[ /]+(?P<text>.*)\n$')
MATCH_CONST   = re.compile(r'^const\s+xmlChar\s+(?P<name>\w+)\[\]\s*=\s+(?P<value>.*)\n$')

header = """# $%s$
# 
# PyXMLSec - Python bindings for XML Security library (XMLSec)
#
# Copyright (C) 2003-2005 Easter-eggs, Valery Febvre
# http://pyxmlsec.labs.libre-entreprise.org
#
# Author: Valery Febvre <vfebvre@easter-eggs.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
