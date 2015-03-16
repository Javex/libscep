#include <Python.h>
#include <structmember.h>
#include <scep.h>

typedef struct {
	PyObject_HEAD
	PyObject *handle;
} PySCEP;

static void
handle_destroy(PyObject *handle)
{
	SCEP *_handle = PyCapsule_GetPointer(handle, "scep.handle");
	scep_cleanup(_handle);
}

static int
PySCEP_init(PySCEP *self, PyObject *args, PyObject *kwds)
{
	SCEP_ERROR error;
	SCEP *handle;
	if((error = scep_init(&handle)) != SCEPE_OK){
		PyErr_SetString(PyExc_RuntimeError, scep_strerror(error));
		return 0;
	}

	self->handle = PyCapsule_New(handle, "scep.handle", handle_destroy);
	return 0;
}

static void
PySCEP_cleanup(PySCEP *self)
{
	Py_XDECREF(self->handle);
}

static void
request_destroy(PyObject *req)
{
	X509_REQ *_req = PyCapsule_GetPointer(req, "scep.req");
	X509_REQ_free(_req);
}

static PyObject *
PySCEP_load_X509_REQ(PySCEP *self, PyObject *args)
{
	char *req_pem;
	X509_REQ *req;
	BIO *b;
	if(!PyArg_ParseTuple(args, "s", &req_pem))
		return NULL;
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, req_pem);
	if(!(req = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL))) {
		PyErr_SetString(PyExc_RuntimeError, "Error loading request from PEM.");
		return NULL;
	}
	return PyCapsule_New(req, "scep.req", request_destroy);
}

static void
certificate_destroy(PyObject *cert)
{
	X509 *_cert = PyCapsule_GetPointer(cert, "scep.cert");
	X509_free(_cert);
}

static PyObject *
PySCEP_load_X509(PySCEP *self, PyObject *args)
{
	char *cert_pem;
	X509 *cert;
	BIO *b;
	if(!PyArg_ParseTuple(args, "s", &cert_pem))
		return NULL;
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, cert_pem);
	if(!(cert = PEM_read_bio_X509(b, NULL, NULL, NULL))) {
		PyErr_SetString(PyExc_RuntimeError, "Error loading certificate from PEM.");
		return NULL;
	}
	return PyCapsule_New(cert, "scep.cert", certificate_destroy);
}

static void
private_key_destroy(PyObject *key)
{
	EVP_PKEY *_key = PyCapsule_GetPointer(key, "scep.privkey");
	EVP_PKEY_free(_key);
}

static PyObject *
PySCEP_load_PrivateKey(PySCEP *self, PyObject *args)
{
	char *privkey_pem;
	EVP_PKEY *key;
	BIO *b;
	if(!PyArg_ParseTuple(args, "s", &privkey_pem))
		return NULL;
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, privkey_pem);
	if(!(key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL))) {
		PyErr_SetString(PyExc_RuntimeError, "Error loading private key from PEM.");
		return NULL;
	}
	return PyCapsule_New(key, "scep.privkey", private_key_destroy);
}

static PyObject *
PySCEP_pkcsreq(PySCEP *self, PyObject *args)
{
	PKCS7 *p7;
	SCEP *handle;
	SCEP_ERROR error;
	X509 *sig_cert, *enc_cert;
	EVP_PKEY *sig_key;
	X509_REQ *req;
	char *b64_out;
	PyObject *sig_cert_cap, *enc_cert_cap, *sig_key_cap, *req_cap;
	if(!PyArg_ParseTuple(args, "OOOO", &req_cap, &sig_cert_cap, &sig_key_cap, &enc_cert_cap))
		return NULL;

	req = PyCapsule_GetPointer(req_cap, "scep.req");
	if(!req)
		return NULL;
	sig_cert = PyCapsule_GetPointer(sig_cert_cap, "scep.cert");
	if(!sig_cert)
		return NULL;
	sig_key = PyCapsule_GetPointer(sig_key_cap, "scep.privkey");
	if(!sig_key)
		return NULL;
	enc_cert = PyCapsule_GetPointer(enc_cert_cap, "scep.cert");
	if(!enc_cert)
		return NULL;
	handle = PyCapsule_GetPointer(self->handle, "scep.handle");
	if(!handle)
		return NULL;
	if((error = scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cert, handle->configuration->encalg, &p7)) != SCEPE_OK) {
		PyErr_SetString(PyExc_RuntimeError, "Error creating PKCSReq.");
		return NULL;
	}
	if((error = scep_PKCS7_base64_encode(handle, p7, &b64_out))) {
		PyErr_SetString(PyExc_RuntimeError, "Error creating Base64 encoding.");
		return NULL;
	}
	return Py_BuildValue("s", b64_out);
}

static PyMemberDef PySCEP_members[] = {
	{"handle", T_OBJECT_EX, offsetof(PySCEP, handle), 0, "The internal SCEP handle."},
	{NULL}
};

static PyMethodDef PySCEP_methods[] = {
	{"load_X509_REQ", (PyCFunction)PySCEP_load_X509_REQ, METH_VARARGS, "Load X509_REQ from PEM string."},
	{"load_X509", (PyCFunction)PySCEP_load_X509, METH_VARARGS, "Load X509 from PEM string."},
	{"load_PrivateKey", (PyCFunction)PySCEP_load_PrivateKey, METH_VARARGS, "Load EVP_PKEY private key from PEM string."},
	{"pkcsreq", (PyCFunction)PySCEP_pkcsreq, METH_VARARGS, "Create a PKCSReq message."},
	{NULL}
};

static PyTypeObject
PySCEPType = {
   PyObject_HEAD_INIT(NULL)
   0,						 /* ob_size */
   "_scep._SCEP",			   /* tp_name */
   sizeof(PySCEP),		 /* tp_basicsize */
   0,						 /* tp_itemsize */
   (destructor)PySCEP_cleanup, /* tp_dealloc */
   0,						 /* tp_print */
   0,						 /* tp_getattr */
   0,						 /* tp_setattr */
   0,						 /* tp_compare */
   0,						 /* tp_repr */
   0,						 /* tp_as_number */
   0,						 /* tp_as_sequence */
   0,						 /* tp_as_mapping */
   0,						 /* tp_hash */
   0,						 /* tp_call */
   0,						 /* tp_str */
   0,						 /* tp_getattro */
   0,						 /* tp_setattro */
   0,						 /* tp_as_buffer */
   Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags*/
   "_SCEP internal class",		/* tp_doc */
   0,						 /* tp_traverse */
   0,						 /* tp_clear */
   0,						 /* tp_richcompare */
   0,						 /* tp_weaklistoffset */
   0,						 /* tp_iter */
   0,						 /* tp_iternext */
   PySCEP_methods,		 /* tp_methods */
   PySCEP_members,		 /* tp_members */
   0,						 /* tp_getset */
   0,						 /* tp_base */
   0,						 /* tp_dict */
   0,						 /* tp_descr_get */
   0,						 /* tp_descr_set */
   0,						 /* tp_dictoffset */
   (initproc)PySCEP_init,  /* tp_init */
   0,						 /* tp_alloc */
   0,						 /* tp_new */
};

static PyMethodDef ScepMethods[] = {
	{NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
init_scep(void)
{
	PyObject *scep = Py_InitModule("_scep", ScepMethods);

	PySCEPType.tp_new = PyType_GenericNew;
	if(PyType_Ready(&PySCEPType) < 0)
		return;

	Py_INCREF(&PySCEPType);
	PyModule_AddObject(scep, "_SCEP", (PyObject *)&PySCEPType);
}