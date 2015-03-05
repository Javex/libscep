import scep._scep as _scep

class SCEP(object):

    def __init__(
            self, url, ca_cert=None, proxy=None, encryption_algorithm=None,
            signature_algorithm=None):
        self._scep = _scep._SCEP()
        self.url = url

    def pkcsreq(self, request, sig_cert, sig_key, enc_cert):
        _request = self._scep.load_X509_REQ(request)
        _sig_cert = self._scep.load_X509(sig_cert)
        _sig_key = self._scep.load_PrivateKey(sig_key)
        _enc_cert = self._scep.load_X509(enc_cert)
        msg = self._scep.pkcsreq(_request, _sig_cert, _sig_key, _enc_cert)
        print(msg)
    


def pkcsreq(url, request, sig_cert, sig_key, enc_cert, enc_alg, proxy=None):
    _scep.create_handle(url, proxy)


if __name__ == '__main__':
    req = """-----BEGIN CERTIFICATE REQUEST-----
MIIBtTCCAR4CAQAwVzELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUx
ITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEQMA4GA1UEAxMHZm9v
LmJhcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApws+aot5FvGrzwj4Zijl
MEkaQnKjotER97Rm7q7QqB5eep4S919V7r/t3uh1ku+CDlm8LmVwA3UlrMBTHnyb
oeg+LUQAs74Gzrl2scaKY/T2J4njbpwEzZdTtX8tUBt7iYsvkLkHt/8XyCMCFbb7
MeXJDH0R5OIOJbDicC6HyL8CAwEAAaAeMBwGCSqGSIb3DQEJBzEPEw1GT09CQVJU
RVNUUFdEMA0GCSqGSIb3DQEBBQUAA4GBACHwu5U6KNAsgFkmgU6DNBQXriPwRvvn
uGCzClbjbwGnoi9XCtgepO6I6AbDokjpuuU8/JEGAqKwtRzOsvGJyq4tphAPf/89
/H+xoHva5tgIGv9zUQSj/6Q0B7TEUKLfVC4H0K9wde+5g13l82EzXXrsCjnyB3S7
SLYGjIEJ2RwX
-----END CERTIFICATE REQUEST-----"""
    sig_cert = """-----BEGIN CERTIFICATE-----
MIICLzCCAZgCCQDTeVgTQPW40zANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJE
RTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRQwEgYDVQQDEwtmb28uYmFyLmNvbTAgFw0xNTAyMjYxMjAwMzla
GA8yMTE1MDIwMjEyMDAzOVowWzELMAkGA1UEBhMCREUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UE
AxMLZm9vLmJhci5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANFEiTNr
xDGehD636meTlC2yAmINuZn7pU9CC4BudfdDAI2YdoB9h9YqRk773EYAveAfSMYg
/ySzMlzz+yb8skZwctrocJYGpgB4N0BpmkGt7VSK9qwT4mRXqL6G2Cvvifi4BBYP
Q4c5JvYP43cDd7/Yb7Hg3Do8tG16Zo6AXaFpAgMBAAEwDQYJKoZIhvcNAQEFBQAD
gYEAbUXoPS+AhHuO7T7KRdgwJDLyr15dwUplGwtZT+MoOnnDMRWv/0VG4QUbBwvP
5Jrrk/lRHKajXLmzrqaoiadGzj6vCOh+zuf/KAOhQjvYtZyL0b727W1Sf2i7Cij+
ublOOHR0hldn/XqR7hKfZ/uIPnznQeKkVGjrEs223vtf7cI=
-----END CERTIFICATE-----"""
    sig_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDRRIkza8QxnoQ+t+pnk5QtsgJiDbmZ+6VPQguAbnX3QwCNmHaA
fYfWKkZO+9xGAL3gH0jGIP8kszJc8/sm/LJGcHLa6HCWBqYAeDdAaZpBre1Uivas
E+JkV6i+htgr74n4uAQWD0OHOSb2D+N3A3e/2G+x4Nw6PLRtemaOgF2haQIDAQAB
AoGBAM9w9eRwLmLVdNhLLeSQqXGGpNAYNOTMTDk+CfK9DNkXpQO3n7iNN0r4Swve
pKML9yylNlmYufLiY8k63brvAbP/Tfg2cbzg47fv+kacqYgaH6aoII++UEAoF+pM
HgdINRIRn+wknsNxdxE+YEJW/+XfhHiwD31RKBFOYw0NL3PRAkEA+pTwf1CfXBLP
Ujap10y883PQpX+lLyFzMT2BEu5C1WfUSjHiyzZyb6utYZ9U1PlTvaUXSJ3guNcl
VVvwjll/rQJBANXK6H9xy959Y7EKfxT41BDHQoXfmEIcLSz1wgWSeKwgbFF4+n3g
JoHG1n4hQ7D6OV41oh18XXYFBE9Ienyw8C0CQEHs0WENev+kSzsb+o8UN1ntjGUe
Mf02VbIMtlqeqKKwkF98xGgmSPEsP49BdfYaKnfoaTnHn4nBwKa2a5Fn5nkCQQCr
nApwcmnRGBlzvRcxQGMJbMjrKQXQ20kv871gN6iBki0gYNnBPLHsLi1yZUUuxExU
YPzWakOjPnetJGKdwHGpAkEAnMDbIjYpg9WYtx4l5q8R8u1USf8ndybDQehite7W
nzpG25y4ERn1b0M8TJ0xK0y2b8pMWBYlavUYkCYCfWOAsw==
-----END RSA PRIVATE KEY-----"""
    enc_cert = """-----BEGIN CERTIFICATE-----
MIICLzCCAZgCCQDTeVgTQPW40zANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJE
RTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRQwEgYDVQQDEwtmb28uYmFyLmNvbTAgFw0xNTAyMjYxMjAwMzla
GA8yMTE1MDIwMjEyMDAzOVowWzELMAkGA1UEBhMCREUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UE
AxMLZm9vLmJhci5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANFEiTNr
xDGehD636meTlC2yAmINuZn7pU9CC4BudfdDAI2YdoB9h9YqRk773EYAveAfSMYg
/ySzMlzz+yb8skZwctrocJYGpgB4N0BpmkGt7VSK9qwT4mRXqL6G2Cvvifi4BBYP
Q4c5JvYP43cDd7/Yb7Hg3Do8tG16Zo6AXaFpAgMBAAEwDQYJKoZIhvcNAQEFBQAD
gYEAbUXoPS+AhHuO7T7KRdgwJDLyr15dwUplGwtZT+MoOnnDMRWv/0VG4QUbBwvP
5Jrrk/lRHKajXLmzrqaoiadGzj6vCOh+zuf/KAOhQjvYtZyL0b727W1Sf2i7Cij+
ublOOHR0hldn/XqR7hKfZ/uIPnznQeKkVGjrEs223vtf7cI=
-----END CERTIFICATE-----"""
    scep = SCEP("foo")
    scep.pkcsreq(req, sig_cert, sig_key, enc_cert)