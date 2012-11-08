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

import grizzled.slf4j.Logging
import java.net.URI
import javax.servlet.http.HttpServletResponse.SC_OK
import net.ripe.certification.validator.fetchers.RpkiRepositoryObjectFetcher
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.commons.certification.util.{CertificateRepositoryObjectParserException, Specifications, CertificateRepositoryObjectFactory, Specification}
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.validation.{ValidationString, ValidationResult}
import org.apache.http.HttpResponse
import org.apache.http.client.{ResponseHandler, HttpClient}
import org.apache.http.client.methods.HttpGet
import org.apache.http.util.EntityUtils

class HttpObjectFetcher(httpClient: HttpClient) extends RpkiRepositoryObjectFetcher with Logging {

  val HTTP_DOWNLOAD_METRIC = "http.download.file"

  override def prefetch(uri: URI, result: ValidationResult) {}

  override def fetch(uri: URI, fileContentSpecification: Specification[Array[Byte]], result: ValidationResult) = {
    downloadFile(uri, result) match {
      case Some(content: Array[Byte]) =>
        if (fileContentSpecification.isSatisfiedBy(content)) {
          result.pass(ValidationString.VALIDATOR_FILE_CONTENT, uri.toString)
          try {
            val cro = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(content, result)
            result.pass(ValidationString.KNOWN_OBJECT_TYPE, uri.toString)
            cro
          } catch {
            case e: CertificateRepositoryObjectParserException =>
              result.error(ValidationString.KNOWN_OBJECT_TYPE, uri.toString)
              null
          }
        } else {
          result.error(ValidationString.VALIDATOR_FILE_CONTENT, uri.toString)
          null
        }
      case None =>
        null
    }
  }

  def downloadFile(uri: URI, result: ValidationResult): Option[Array[Byte]] = {
    try {
      val now = System.currentTimeMillis()
      httpClient.execute(new HttpGet(uri), responseHandler(uri)) match {
        case Some(content) =>
          result.pass(ValidationString.VALIDATOR_HTTP_DOWNLOAD, uri.toString)
          result.addMetric(HTTP_DOWNLOAD_METRIC, String.valueOf(System.currentTimeMillis()-now))
          Some(content)
        case None =>
          result.error(ValidationString.VALIDATOR_HTTP_DOWNLOAD, uri.toString)
          None
      }
    } catch {
      case e: Exception =>
        result.error(ValidationString.VALIDATOR_HTTP_DOWNLOAD, uri.toString)
        None
    }
  }

  def responseHandler(uri: URI): ResponseHandler[Option[Array[Byte]]] = new ResponseHandler[Option[Array[Byte]]]() {
    override def handleResponse(response: HttpResponse): Option[Array[Byte]] = {
      response.getStatusLine.getStatusCode match {
        case SC_OK =>
          Some(EntityUtils.toByteArray(response.getEntity))
        case _ =>
          EntityUtils.consume(response.getEntity)
          None
      }
    }
  }
}
