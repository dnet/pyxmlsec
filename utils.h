#ifndef __PYXMLSEC_UTILS_H__
#define __PYXMLSEC_UTILS_H__

#undef _POSIX_C_SOURCE
#include <Python.h>

extern PyObject *xmlsec_error;

int CheckArgs(PyObject *args, char *format);

#endif /* __PYXMLSEC_UTILS_H__ */
