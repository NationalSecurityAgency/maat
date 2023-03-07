/*
 * Copyright 2023 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*! \file
 * These certificates and keys are to be used for demo purposes only.
*/

#include "iota_certs.h"
#include <stdint.h>
char tz_privkey_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIIEogIBAAKCAQEAsyhPrrIgkelZAMvtwd7V1Pps+C2PxfQ3CfCorjYf193lET7M\n"
                        "HdA6czT4dAOoSBlLcpcl0SjFXwdUr2b8U2InhYDAYFyXDeL4WcnFxCLJ8EntZPtB\n"
                        "LrGg3EYIWpor/wbPsIujBlbN704/5B0D85SslzHc3DVa6YlB6ucN3u28qaqnxKgu\n"
                        "yGgaG8viRQid0i3tagWqgblcs33iLvIX4qeGJBIJJ918/eIa+URX66Gl0x4dBNPr\n"
                        "bE6hJo393V7tYDGSIci3UgP+QlAhHgyBwXRAv7UlvS59qj6lu5Rh0ADoOvFZcvuI\n"
                        "8okOM3faHHZUYOJdplC7OLEwupOkQDtSWqcN4wIDAQABAoIBAFI2e2pVP3D1vewJ\n"
                        "qM9AbKvRR1QTxFg4m1EqaJ2ZJL+wib+CK7S6qzfW5PSIAR8kzGSHS8lRhlD3Ujsz\n"
                        "bTLuZehzjtQpaP/sWb8KQoCg3j4wDoo6akz9Ii4yzP6WpP3gqEoBqgvspY/dPqB1\n"
                        "WCzc2t5++TTsHw3v+JnM8aaNPfg1HSkuGTvwOoaNtVE31vmcDbegydJSKoug1lQM\n"
                        "bKI+Jv+PpfcDkeQmaOIJGDg6Go3CkE7aynJ50KbUz/KMz5Wxugudih6EA3LyzUqe\n"
                        "Q2bB9GcKCvQgoyDgqFLhEYoehOlZ37diETkNRIz6KXIegXdHajNEZPZ9jhTFwldB\n"
                        "WufLPyECgYEA3HMEG/AN8CjZ8lN4UOHXcOksLTJxgHo8dERghPctvY8qRf0JusTK\n"
                        "xvv+tmPVRLdYnY8BBHrgX1xUrtpGvv9A3sNv7EKNmiwNSsnSZEXqA3sRRU8Zz6lt\n"
                        "ibvL7wem/V5MkF+L479M0TgzCaZaorq63KLF0cK6ouZA5nrwrhyE08sCgYEA0Ayc\n"
                        "tyZhf19FZLDgiUMNTZGqZ2gRmGHQSKRIzf1hBOKvf/ccNT58QjHchLsBfVqD0O2i\n"
                        "VjBEOwI0nscx+O8VyFk52DhSD4RomI0pS2xpGXTvcwLP0jxe9zrUacQ2t/nrYK/c\n"
                        "U166qrQVJEEguEGmccEBUQxjgc6jaWef2UPI20kCgYBN/dsMT0d/GdTRqLo+U0g3\n"
                        "SCc67ke9noFY2QAUyqZCFC5uiHEyxIDBGVIqEPPY1cziIT/I5/gNhMro+Yxh8khv\n"
                        "B1HHklwqmT8yoGhw1VNPW/DmRm/pShXYzrn9nQV1SjFoOoVxU7LHqkxUM6iJPery\n"
                        "OBwoc+43x6JaaFBSKQDNNQKBgAo5pHYn78DH2OxC+TYl0oCOeTaN2deIbyky0dU1\n"
                        "78/CqGd8qKlBQfAq7TCk1ETp7vKUy1a7Fo9j41wuZBlc/tAS+pHS6s2Sb2WYAoCP\n"
                        "enbi1WXsrHQjvXMfNBNirmHKabQd0JFUZY5APY3Dma0UpO6QUtU966IUmtlyW1vd\n"
                        "RgDpAoGAJczH64ISiuTLFBfiUJ8L/hFkI21xoNByxuA/x2ms/2NNqpf6q271lUHC\n"
                        "xngUiLM71mn5JybGrAqNen7yqOElIqe7PTu2hLwz8Z18kqGlzAnpZ92xIVPKPZTQ\n"
                        "o6NmxQfaOq0rWPxqHH46hUNbshvHf/b4kQ419mEhyluZbeg/h9I=\n"
                        "-----END RSA PRIVATE KEY-----\n";

const uint32_t  tz_privkey_pem_sz = 1675 + 1;

char tz_pubcert_pem[] = "-----BEGIN CERTIFICATE-----\n"
                        "MIIDETCCAfkCFGhMhJv2XG3tlK28LXUhZj+IXvXNMA0GCSqGSIb3DQEBCwUAMEUx\n"
                        "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
                        "cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkwOTIzMTU0NTQyWhcNMjEwMjA0MTU0\n"
                        "NTQyWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\n"
                        "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
                        "AQ8AMIIBCgKCAQEAsyhPrrIgkelZAMvtwd7V1Pps+C2PxfQ3CfCorjYf193lET7M\n"
                        "HdA6czT4dAOoSBlLcpcl0SjFXwdUr2b8U2InhYDAYFyXDeL4WcnFxCLJ8EntZPtB\n"
                        "LrGg3EYIWpor/wbPsIujBlbN704/5B0D85SslzHc3DVa6YlB6ucN3u28qaqnxKgu\n"
                        "yGgaG8viRQid0i3tagWqgblcs33iLvIX4qeGJBIJJ918/eIa+URX66Gl0x4dBNPr\n"
                        "bE6hJo393V7tYDGSIci3UgP+QlAhHgyBwXRAv7UlvS59qj6lu5Rh0ADoOvFZcvuI\n"
                        "8okOM3faHHZUYOJdplC7OLEwupOkQDtSWqcN4wIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                        "A4IBAQBTVnKts7QQvgZ1qu8lzBY+yKIZGa71LTx8WfwoWITmnBpNj+m+NyLAJokx\n"
                        "0Wz5LAGvwf9EguZ1RRhUT6sO+vJAfd0vXpx1Ls7PMs3RBa0g9DNAFjLQ0p5Zy/+g\n"
                        "LcS0XqmJrqbu+//ytl4xWZMCz/7cbcEpjYHdU1T6rtNKh28qCaKLmvrMwJ5uMOas\n"
                        "pZ0LN0Kkz64eLAi/68pf09jbUhrC0OHu0fJglgqGaY1DOPcEuAYx+eZHdAzf8HsN\n"
                        "hSSLcTh9YuA8CVlbtGOCEowkgysqBw/xiN4G1kjNwQ1xmwZKAcwX+MxIQdCWUoyD\n"
                        "lnC8jVujjbe0tkz5Lfv6K4rsISlq\n"
                        "-----END CERTIFICATE-----\n";

const uint32_t  tz_pubcert_pem_sz = 1123 + 1;

char ns_privkey_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIIEowIBAAKCAQEAyIbSsCKLkbUYihVzz7BCuSPL1qCeehIyRK04EbYSqkWTBgMd\n"
                        "LJaWrOl7NFpWQyevuRV6DAB8z1ujc6YydOrbNUFRNOMXI+vEyGdBKQ7XafDDPiCo\n"
                        "TVSvmlLDLDGORV1osnaUpAFK61qAmBhhFWqT3cK2bMJQXlql9dTHmJWuwzrKEk0g\n"
                        "GNADfvYFRN4IPuClnxLKCic6A4hFhQkOiuTdhrUJplFg+rA/ZLOnqEL6jAOpRiPX\n"
                        "7GG5Hjd+61wI9zjo0pqygaXr8bs0hpes66OEYCRGEt8fAAWPvxIhu5dlv0rDSWZd\n"
                        "S+ywrpSEvHdPD7kjO/bxiUR11Ze5diMzIhmFQQIDAQABAoIBAEp7wdCI1FzH7piD\n"
                        "xWO0reQFBtbvDE59acyWpsf1YFN8ylKmX3TLbqZFh2z3zSjemefesVm56KJBAKKZ\n"
                        "bg59mfTbESXa4CKIlax2pf5xM9R3CJ6QFNO8jAl/il1k/tqHCreXUjjk/gYTtMZJ\n"
                        "7+27i7cIdyhIuP+DHjgE1Cq6FpMPH1nGhtUgF/aleNlXMhTFHmMLt3nC/LHl9VMh\n"
                        "MPkC2XZw/quU9w1d65yOsrsyomf0hxSvUSOltdf/dycnPXZnPQk3KVsE92vbRTq8\n"
                        "j5g9a9u+uJ3SB4vEejvEvwCPW+e+6HA+I38N0+AZ0TICrn0gqmhU2RsTvsKmYJrZ\n"
                        "Uod0klECgYEA9X5LA3yyzh21/sjs07OLRnvPMjgw10H7utxYXhH/cXwdWtBUM2sz\n"
                        "tt+F68bEI2axndZKUk21DSz1mTydNtHZMT9X+Bsp//PIyuyaxWzM6zJfGDYRsCa8\n"
                        "IPvEASv9aymseSefFz4vi6yS9iE6FxkkSlCT9GUUkoRq7p2g4DuI/sUCgYEA0Rvc\n"
                        "KYxyCwswp9wdK3VfihBYEBylFDMxSetTtom+yllgWDo+0IIWwY5VzFm/DrqnVQHY\n"
                        "IrlooCVno4yVhvJ6UaKiLeDxnc38KQfq8FeBwwLbewaj68kPUbbP3AsnjkvZEvuG\n"
                        "ON02gRRULloUvGB4GbisjoftBs5BVrNYUUXflE0CgYEAtkRISZSB5QqmHz7qptt9\n"
                        "Ip213iFeEdQJpFkIuv892vI9kTlv6qVDRhl7Au0WnvoWEYwSrjzHmbqxtk4Mo7D2\n"
                        "Qtw24hy4+DH1+MPmvYHkOxOxCvbJ9zErKIoEoqIYi0HrriA+vDENd/RvQJK24INo\n"
                        "MEzXLPMHbSkng3ZBBXruYckCgYBHzA8N3QETNaZhHDyPvV8uYmo6LfuoMeOMg9Zc\n"
                        "aHMvuvxPjsAei2wQzTQ8U9w7zG7DyzxQv+RiiDVLfGuiyAKjoPmaUw/ipOUdmXBb\n"
                        "UVBmisadOSxzOred0O0RmmrcesJvuBjf0WRzcW1t9NQF0gGqozPsRFNn8M2SXUXH\n"
                        "sfwQSQKBgEwtkQuWIyfmv2mbXcDqz+VDf/ojNHqz3N+PH8nqEHrYo9glwa2nEtNO\n"
                        "i1h1esl9vG9yZcnME53cnpizO9FO2j3thD5kPqz/bodLjTS/NmPSutzwdTvejQpJ\n"
                        "XQZBcqaWDx0j8eTU0YsVMJb4GZCEPtFqEwLzooAQxRj4np57K1Gj\n"
                        "-----END RSA PRIVATE KEY-----\n";

const uint32_t  ns_privkey_pem_sz = 1675+1; // add one for \0

char ns_pubcert_pem[] = "-----BEGIN CERTIFICATE-----\n"
                        "MIIDETCCAfkCFGhMhJv2XG3tlK28LXUhZj+IXvXOMA0GCSqGSIb3DQEBCwUAMEUx\n"
                        "CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\n"
                        "cm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTkwOTIzMTcyODM5WhcNMjEwMjA0MTcy\n"
                        "ODM5WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\n"
                        "CgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
                        "AQ8AMIIBCgKCAQEAyIbSsCKLkbUYihVzz7BCuSPL1qCeehIyRK04EbYSqkWTBgMd\n"
                        "LJaWrOl7NFpWQyevuRV6DAB8z1ujc6YydOrbNUFRNOMXI+vEyGdBKQ7XafDDPiCo\n"
                        "TVSvmlLDLDGORV1osnaUpAFK61qAmBhhFWqT3cK2bMJQXlql9dTHmJWuwzrKEk0g\n"
                        "GNADfvYFRN4IPuClnxLKCic6A4hFhQkOiuTdhrUJplFg+rA/ZLOnqEL6jAOpRiPX\n"
                        "7GG5Hjd+61wI9zjo0pqygaXr8bs0hpes66OEYCRGEt8fAAWPvxIhu5dlv0rDSWZd\n"
                        "S+ywrpSEvHdPD7kjO/bxiUR11Ze5diMzIhmFQQIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                        "A4IBAQBIWDjRJBmJjtiDFED2NFPNXFJ3as8ZqRYChXXi3Blt2kN5IpSbvHunVa4F\n"
                        "EtMNJ/k7GFcp9Dur8nIoE9POHf8PCuOH+WnR5HpJvUaZcxz2q5lrl2XbnIIefInW\n"
                        "bC+H7rDsw5NKMOV2a6glWM36tmjCXOaelSo6OPcyR/SH3ZBisTrzNjKrbl2vaIAu\n"
                        "GMk4TfU3omhbUoE7wMdOoJPSDnE49Jf5nlwiCuAYv2iD275gKtZRC4zAWjQhsa/X\n"
                        "iNY/HiiFF2zxFbYxkbN2NjVUoUJUO8CPeKVpPmcJtVEFqT6dRI8fOq9odQj1m29W\n"
                        "ssdZ0i9Vkz55i7Dk0MTHk+1ficb1\n"
                        "-----END CERTIFICATE-----\n";


const uint32_t  ns_pubcert_pem_sz = 1123 + 1;

