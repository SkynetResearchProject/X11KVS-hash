#define PY_SSIZE_T_CLEAN //Fixes Python3.10 error "SystemError: PY_SSIZE_T_CLEAN macro must be defined for '#' formats"
#include <Python.h>

#include "x11kvshash.h"

static PyObject *x11kvs_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    x11kvs_hash((char *)PyBytes_AsString((PyObject*) input), output);
#else
    x11kvs_hash((char *)PyString_AsString((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef XcoinMethods[] = {
    { "getPoWHash", x11kvs_getpowhash, METH_VARARGS, "Returns the proof of work hash using x11kvs hash" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef XcoinModule = {
    PyModuleDef_HEAD_INIT,
    "x11kvs_hash",
    "...",
    -1,
    XcoinMethods
};

PyMODINIT_FUNC PyInit_x11kvs_hash(void) {
    return PyModule_Create(&XcoinModule);
}

#else

PyMODINIT_FUNC initx11kvs_hash(void) {
    (void) Py_InitModule("x11kvs_hash", XcoinMethods);
}
#endif
