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
package net.ripe.rpki.validator.fetchers

import org.scalatest.{BeforeAndAfter, FunSuite}
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.mock.MockitoSugar
import org.apache.http.client.{ResponseHandler, HttpClient}
import java.net.URI
import net.ripe.commons.certification.validation._
import org.mockito.Mockito._
import org.apache.http.client.methods.HttpGet
import scala.Some
import org.mockito.Matchers.any
import net.ripe.commons.certification.crl.X509CrlTest
import net.ripe.commons.certification.util.Specifications
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class HttpObjectFetcherTest extends FunSuite with ShouldMatchers with BeforeAndAfter with MockitoSugar {

  val uri: URI = URI.create("http://repository/ca/sample.crl")
  val crl = X509CrlTest.createCrl
  val content = crl.getEncoded

  val mft = ManifestCmsTest.getRootManifestBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)

  val httpClient = mock[HttpClient]
  val subject = new HttpObjectFetcher(httpClient)


  def resetHttpClient() {
    reset(httpClient)
  }

  before {
    resetHttpClient()
  }

  def validationResultForLocation(uri: URI) = {
    val validationResult = new ValidationResult
    validationResult.setLocation(new ValidationLocation(uri))
    validationResult
  }

  test("should http client return downloaded content as byte array") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenReturn(Some(content))

    subject.downloadFile(uri, validationResult) should be (Some(content))
    validationResult.getFailuresForAllLocations should be ('empty)
  }

  test("should http client return None and set failure if downloading fails") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenThrow(new RuntimeException)

    subject.downloadFile(uri, validationResult) should be (None)
    validationResult.getFailuresForAllLocations should contain (new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_HTTP_DOWNLOAD, uri.toString))
  }

  test("should get object") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenReturn(Some(content))

    subject.fetch(uri, Specifications.alwaysTrue(), validationResult) should equal (crl)
    validationResult.getFailuresForAllLocations should be ('empty)
  }

  test("should get object set failure if specification does not match") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenReturn(Some(content))

    subject.fetch(uri, Specifications.alwaysFalse(), validationResult) should be (null)
    validationResult.getFailuresForAllLocations should contain (new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_FILE_CONTENT, uri.toString))
  }

  test("should get object  set failure if object is unkown") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenReturn(Some(Array[Byte](1)))

    subject.fetch(uri, Specifications.alwaysTrue(), validationResult) should be (null)
    validationResult.getFailuresForAllLocations should contain (new ValidationCheck(ValidationStatus.ERROR, ValidationString.KNOWN_OBJECT_TYPE, uri.toString))
  }

  test("should get object return null and set error if download failed") {
    val validationResult = validationResultForLocation(uri)
    when(httpClient.execute(any[HttpGet](), any[ResponseHandler[Option[Array[Byte]]]]())).thenReturn(None)

    subject.fetch(uri, Specifications.alwaysTrue(), validationResult) should be (null)
    validationResult.getFailuresForAllLocations should contain (new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_HTTP_DOWNLOAD, uri.toString))
  }
}
