#ifndef __PYXMLSEC_XMLSECMOD_H__
#define __PYXMLSEC_XMLSECMOD_H__

#include <xmlsec/crypto.h>

#include <xmlsec/base64.h>
#include <xmlsec/buffer.h>
#include <xmlsec/errors.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keys.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/list.h>
#include <xmlsec/membuf.h>
#include <xmlsec/nodeset.h>
#include <xmlsec/parser.h>
#include <xmlsec/templates.h>
#include <xmlsec/transforms.h>
#include <xmlsec/version.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/x509.h>

#include "utils.h"
#include "wrap_objs.h"

#define HASH_TABLE_SIZE 10

extern PyObject *xmlsec_error;

#endif /* __PYXMLSEC_XMLSECMOD_H__ */
