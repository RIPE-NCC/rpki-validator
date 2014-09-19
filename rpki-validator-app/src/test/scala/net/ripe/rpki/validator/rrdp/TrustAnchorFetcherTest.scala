/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.validator.rrdp

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import net.ripe.rpki.validator.support.ValidatorTestCase
import java.net.URI
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.rpki.validator.models.ValidObject
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import org.scalatest.mock.MockitoSugar
import org.apache.http.client.HttpClient
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import org.apache.commons.codec.binary.Base64
import net.ripe.rpki.commons.validation.ValidationResult

@RunWith(classOf[JUnitRunner])
class TrustAnchorFetcherTest extends ValidatorTestCase with MockitoSugar {

  val TAL =
    "http://localhost:8080/rpki-ca/ta/ta.cer\n" +
      "\n" +
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs7lLXcBnMsire5rW\n" +
      "E6JV86m4QZpVCX5qUnbrQunqMYRlyCpuGaYkBGYyMz6q9oMO6OLr26B0RfQg\n" +
      "12r3zsRq2YD3xqgCtsvjY/jv3xXiNlrXiBlvmeQlzl58F6jM6EOGHW+9g5BB\n" +
      "5xSZfC8wpOztx1nhCivXXfyfcm6+YlHWmCN5RUWjzhDfi5MwdpVe2TQt+v1O\n" +
      "+tlkJA+KVM1WfQDUtKCFYJwufxUsVAXoHDxh5mLvHlcAIicIQkUHpnPlaE76\n" +
      "VHJQROBAShEw22krFoAk5lwqkeyuw1wAu3NH0UpCiABm5GkR6FP8erM6HcsX\n" +
      "EPToHNz2zKOTqek6yHrrl8IXqwIDAQAB"

  val TA_CERT_BASE64 = "MIIEHzCCAwegAwIBAgIBATANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDEwJUQTAeFw0xNDA5MTkwOTA5MTFaFw0xOTA5MTkwOTA5MTFaMA0xCzAJBgNVBAMTAlRBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs7lLXcBnMsire5rWE6JV86m4QZpVCX5qUnbrQunqMYRlyCpuGaYkBGYyMz6q9oMO6OLr26B0RfQg12r3zsRq2YD3xqgCtsvjY/jv3xXiNlrXiBlvmeQlzl58F6jM6EOGHW+9g5BB5xSZfC8wpOztx1nhCivXXfyfcm6+YlHWmCN5RUWjzhDfi5MwdpVe2TQt+v1O+tlkJA+KVM1WfQDUtKCFYJwufxUsVAXoHDxh5mLvHlcAIicIQkUHpnPlaE76VHJQROBAShEw22krFoAk5lwqkeyuw1wAu3NH0UpCiABm5GkR6FP8erM6HcsXEPToHNz2zKOTqek6yHrrl8IXqwIDAQABo4IBiDCCAYQwHQYDVR0OBBYEFEXod0w+nYwOpNNqkR6uCW55OJ7XMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMIHPBggrBgEFBQcBCwSBwjCBvzApBggrBgEFBQcwBYYdcnN5bmM6Ly9sb2NhbGhvc3Q6MTA4NzMvcmVwby8wVQYIKwYBBQUHMAqGSXJzeW5jOi8vbG9jYWxob3N0OjEwODczL3JlcG8vNDVlODc3NGMzZTlkOGMwZWE0ZDM2YTkxMWVhZTA5NmU3OTM4OWVkNy5tZnQwOwYIKwYBBQUHMA2GL2h0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9ycGtpLWNhL25vdGlmeS9ub3RpZnkueG1sMBgGA1UdIAEB/wQOMAwwCgYIKwYBBQUHDgIwMwYIKwYBBQUHAQcBAf8EJDAiMBQEAgABMA4DAgAKAwMErBADAwDAqDAKBAIAAjAEAwIB/DAhBggrBgEFBQcBCAEB/wQSMBCgDjAMMAoCAwD8AAIDAP/+MA0GCSqGSIb3DQEBCwUAA4IBAQASmd+JDZ2umcemY1XdiaygRHXORGSxH9JypbdUzfdjBziCjo1i3nx4o/Vv5R0td+J2Sl0ysJDw70Gt72DVfglu7wAbkonm+jR/HqeK+K61G5o8RofU1NxcnuQFlAtlpqxIQdztiGJI/c93g6G2onpwwv49nhYvzARgEnL8twD3wsYWrOifF43OfFd6V2RTF3KpbSL6vx4gqVGvGebIS1BfTzj2g7h/HxI7lwadBIBSW1tEbzhn73Cw5L1d0Io7MFyUg7KBZ0nrCRlJNvv8KlSjXfW4HwVHuJFpBKRxBolj3oN/Cl4Np+l1hUdyO1BIcQWDw84tD6szIg75wI4puGU6"
  val TA_CERT = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(Base64.decodeBase64(TA_CERT_BASE64), ValidationResult.withLocation(URI.create("http://localhost:8080/rpki-ca/ta/ta.cer")))

  test("should read TA") {
    val fetcher = TrustAnchorFetcher.fromString(TAL)
    fetcher.uri should equal(URI.create("http://localhost:8080/rpki-ca/ta/ta.cer"))
    fetcher.publicKeyInfo should equal("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs7lLXcBnMsire5rWE6JV86m4QZpVCX5qUnbrQunqMYRlyCpuGaYkBGYyMz6q9oMO6OLr26B0RfQg12r3zsRq2YD3xqgCtsvjY/jv3xXiNlrXiBlvmeQlzl58F6jM6EOGHW+9g5BB5xSZfC8wpOztx1nhCivXXfyfcm6+YlHWmCN5RUWjzhDfi5MwdpVe2TQt+v1O+tlkJA+KVM1WfQDUtKCFYJwufxUsVAXoHDxh5mLvHlcAIicIQkUHpnPlaE76VHJQROBAShEw22krFoAk5lwqkeyuw1wAu3NH0UpCiABm5GkR6FP8erM6HcsXEPToHNz2zKOTqek6yHrrl8IXqwIDAQAB")
  }

  test("Should retrieve and validate certificate") {

    val fetcher = TrustAnchorFetcher.fromString(TAL, new TestRetriever(TA_CERT))

    fetcher.fetch match {
      case invalid: InvalidObject => fail("Should have found a valid certificate: " + invalid.checks)
      case valid: ValidObject => valid.repositoryObject.isInstanceOf[X509ResourceCertificate] should be(true)
    }
  }

}