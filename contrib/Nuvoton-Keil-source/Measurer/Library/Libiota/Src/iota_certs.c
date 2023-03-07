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

#include "iota_certs.h"
const char tz_privkey_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"
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

const int  tz_privkey_pem_sz = 1675 + 1;

const char tz_pubcert_pem[] = "-----BEGIN CERTIFICATE-----\n"
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

const int  tz_pubcert_pem_sz = 1123 + 1;

