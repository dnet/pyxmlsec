/* $Id$ 
 *
 * PyXMLSec - Python bindings for XML Security library (XMLSec)
 *
 * Copyright (C) 2003-2004 Easter-eggs, Valery Febvre
 * http://pyxmlsec.labs.libre-entreprise.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "wrap_objs.h"

#include "version.h"

PyObject *xmlsec_xmlsec_version(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION));
}

PyObject *xmlsec_xmlsec_version_major(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MAJOR));
}

PyObject *xmlsec_xmlsec_version_minor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_MINOR));
}

PyObject *xmlsec_xmlsec_version_subminor(PyObject *self, PyObject *args) {
  return (wrap_int(XMLSEC_VERSION_SUBMINOR));
}

PyObject *xmlsec_xmlsec_version_info(PyObject *self, PyObject *args) {
  return (wrap_charPtrConst(XMLSEC_VERSION_INFO));
}
