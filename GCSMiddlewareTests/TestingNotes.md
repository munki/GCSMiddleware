## Testing notes

To ensure the Swift implementation produces the same results as the original Python implementation, I hacked up the Python script for the gcs_auth middleware. My local Python install does not include OpenSSL.crypto, so I switched to rsa. Since the CloudFront middleware uses OpenSSL.crypto under Python 2.x, and rsa under Python 3.x, this seems safe enough...

I also needed to modify the gen_signed_url function to take more options instead of calculating the expires time and reading a key and client_id from a file so I could test with consistent values.

The hacked up script follows:

```python
import base64
import datetime
import json
import time
import os


#from OpenSSL.crypto import FILETYPE_PEM
#from OpenSSL.crypto import load_privatekey
#from OpenSSL.crypto import sign

from rsa import PrivateKey
from rsa import sign

# backwards compatibility for python2
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


__version__ = '2.0'
# Our json keystore file
JSON_FILE = 'gcs.json'
JSON_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), JSON_FILE))


def uri_from_url(url):
    parse = urlparse(url)
    return parse.path


def read_json_keystore():
    ks = json.loads(open(JSON_FILE_PATH, 'rb').read().decode('utf-8'))

    if 'client_email' not in ks or 'private_key' not in ks:
        print('JSON keystore doesn\'t contain required fields')

    client_email = ks['client_email']
    key = load_privatekey(FILETYPE_PEM, ks['private_key'])

    return key, client_email


def gen_signed_url(gcs_path, key, client_id, expiration):
    """Construct a string to sign with the provided key and returns \
    the complete url."""
    #expiration = (datetime.datetime.now() + datetime.timedelta(minutes=15))
    #expiration = int(time.mktime(expiration.timetuple()))

    #key, client_id = read_json_keystore()
    canonicalized_resource = '{}'.format(gcs_path)

    tosign = ('{}\n{}\n{}\n{}\n{}'
              .format('GET', '', '',
                      expiration, canonicalized_resource))
    signature = base64.b64encode(sign(tosign.encode("utf8"), key, 'SHA-256')).decode('utf-8')

    final_url = ('https://storage.googleapis.com{}?'
                 'GoogleAccessId={}&Expires={}&Signature={}'
                 .format(gcs_path, client_id, expiration,
                         quote_plus(str(signature))))

    return final_url


def gcs_query_params_url(url):
    file_path = uri_from_url(url)
    url = gen_signed_url(file_path)
    return url


def process_request_options(options):
    """Make changes to options dict and return it."""
    if 'storage.googleapis.com' in options['url']:
        options['url'] = gcs_query_params_url(options['url'])
    return options


PRIVATE_KEY_DATA = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4XZhFX3V4NFUQbZdWmDPEN5KJeRVm9bOJUigDRyD2UfdZbpd
Hy1lddomfxziRlJhuSTEsKBANhdiEv8rkHghtwIlpzzbROMkkbYHZETileAWy4tn
qHtgCBtVvwMU8Rjza9eUJzDdzC/fT7zYcYbAdT8R3Er55A18J8jDuBMzmMQEnNbL
oSIMP5ISPd5bPzG/3gdHsEvLuHweWhGCi1gvfaB6/mssng/wlQOHm6P8NPBcmWAW
gSVyF7xafCQsaS/0GnzhfZCjvTwMiCtoqEkvCQMdMd9yRFSoPm8V85tKRpfnPxOu
3+W2BXnILIg03RdAY9ZLUj7l0FyPTs/BLFqdIwIDAQABAoIBAQCHcR/9UyzK87WU
DEOkaYe68G7GuJadGbuZNjm/5qNmQf/EfuI2OoU6+SQrNGTSLec629W07W/ljsKB
+vxmu2Q1lnqcLrjidzmetyVVnPQpaQcIm+RXmFYmSJWIPAe2lnCVFlqP+JElepTC
SAYWnQa86HiISBo6X8d39ulsiUxzthyL2sHz2FBDyGfXifMi53Xze4C8tqk0jqxc
bTZTquUoPwmn4CNt65vQv5TWyeDeu0M+nHkoemZvtJ2b8/l3C1KjjqSHgODHqhg7
69PInOv9PFKTe6nh38+ARRKbGkQQ25JuULl8WVDMDXVitAb91PPHDSjpH2/towEG
ORvIbVvxAoGBAP8XLy9YrZDaNYGBHivqTDOLFMNFXl2V2UxwsvsRimc/qKHGKv5A
EorzRJ/DJNfNaq4WY+eH/yMtcyD3QAJ5BMgsv6FjpJii7dg3BnQdu+DGSfA5skv5
x6HsUAhCBI2W+rpfLLn6Hwz5VQ2a5/Z1rp/Fa4MMusXtm9/fpKDEY6JFAoGBAOJE
J2kARshHpCV5Tx3Vp1CCOTJyZWnL+P857IYkweCeYnnIzPnTx+JEi0d3v8PxkUuP
Ctq8G5zC6eC0mH4V9J5QOr8UVXVp5v+sX3CaubNEog3m9NfCETW1uLZ7ca2/yASP
dbY/D9tn/rF9jOGuMb/lOOi3fPcOfq52wy3RLexHAoGBANgN9vUPEtLhPvhVOAzS
AYCWiBtsIaT6SnYn7jAghy00CcwbYEbAVfRCXxlB2268mWKhrDRqR3qwABcn05tE
jPxOinBTSRHOzcyXrmui04Jp8C37cDxRbviCgra708do3SwFeIh8hNgkRhmj3lwt
CJ5iQ9FXcso5mhBgB7vzGsBRAoGAeCyqoeI7tfQXArBDjR0FGIWRy3Fm26IyRZyG
O1kagCqfMv+rnqUU7OBq+TJo77FF8lOu+C4gnEoJ3gcNVypiGhOSoBo0qX/t6K2s
oyoKp2Q0jh20vUOd0GEMEh/OaPILUiC/7GPiEC5T4AFG6jaSxdEBQNjzzmQsdI0v
bQ5EzdECgYBAyQe6+LA6PPp19T15zR52yI3A2GCxhnWo85j3J0DBSMfTJkqTkZ8A
qetlov0aId57N48fco3Uno1zybEzUxFMCi7x/04xNY8TpMsPSzHpqgIuGVVtBBz/
YgobcZkFwOQZ+omcKfbH7qs7U8cZ2+eKE+hjUR/+DCH5UEMwUohbAw==
-----END RSA PRIVATE KEY-----"""

# test sign
key = PrivateKey.load_pkcs1(PRIVATE_KEY_DATA.encode('utf8'))
tosign = "FOO_BAR_BAZ"
signature = base64.b64encode(sign(tosign.encode('utf8'), key, 'SHA-256')).decode('utf-8')
print("sign result:")
print(signature)
print()

# test gen_signed_url
gcs_path = "/foo/bar"
client_id = "readonly@double.iam.gserviceaccount.com"
expiration = 1747270308
print("gen_signed_url result:")
print(gen_signed_url(gcs_path, key, client_id, expiration))
print()
```

When run, it produces:

```
sign result:
VWYnp4eMt/OVBmhfE0b3330IAliZrBYOCwGswJbrUbSE2d8iu9ocYB5emvML9YdwH+kGJKBgZSsmFUQsvOQbd7jkRjCukcTkpmMCDjFhKNQolXGQss+J5IGvDgGsgGJuHY42D4uPWrybvLODOS1UDDmwJoYbnz2GTxc2201zYYm0GP0j7Yr+gAvOPDZQoMLXGmF7iwYkF4a/iHhb5Lhn0JHQQwD0en7h1qlyiDCKZfZRo8wjy9q5ddE0Wv2YoHwJecqa3eFnVlcN3ebg29FthQEHTEX0ksslU7wZBYRnpIs2/hxVMsi6HrTkjPaT55SxUmuW4Y+hgdQ157CwtJ4UkQ==

gen_signed_url result:
https://storage.googleapis.com/foo/bar?GoogleAccessId=readonly@double.iam.gserviceaccount.com&Expires=1747270308&Signature=Hga23aNsQKDiLUceCarzz1UQvwOHQMNNunWAFpmIy%2FNwTb%2BfSXz97jXMnWpH16oQLA%2BJZ%2BskeyE3jg8%2FLBdO9Vq6eCdxAaAo%2Fh5UKIgq8jGLd2DqzkLWLYkd77VimhbQdspa5yHz3GSVinYncgfke%2FwdRgqQorTJix33AykskNR7osQD0jrAqvr8tXONm%2F2nbueIEjwCjoTJ%2FDWa3eetKzffCE4vlIl2aQWxQ%2BkwlkY3UdWQa1a%2FGdGGf5axxbZ4OdROJdGTPXP4VfId2XK0PMKZPc2sjO1Mw%2Fzvq211dkEtmiNQ3Yik4PbI80xv3ytONthVENOR9KArRcAQcE3eAw%3D%3D
```

These values were used in the tests to ensure the Swift implementation generated the same signatures and signed URLs.