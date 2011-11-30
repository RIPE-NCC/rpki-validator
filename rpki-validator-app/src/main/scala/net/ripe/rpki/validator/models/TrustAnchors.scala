/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.rpki.validator.models

import scala.collection.JavaConverters._
import java.io.File
import java.net.URI
import grizzled.slf4j.Logging
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.x509cert.X509ResourceCertificate
import net.ripe.certification.validator.util.TrustAnchorExtractor
import net.ripe.certification.validator.util.TrustAnchorLocator
import scalaz.concurrent.Promise
import org.joda.time.DateTime
import scalaz.{Validation, Failure, Success}

sealed trait ProcessingStatus {
  def isIdle: Boolean
  def isRunning: Boolean = !isIdle
}
case class Idle(nextUpdate: DateTime, errorMessage: Option[String] = None) extends ProcessingStatus {
  def isIdle = true
}
case class Running(description: String) extends ProcessingStatus {
  def isIdle = false
}

case class TrustAnchor(
  locator: TrustAnchorLocator,
  status: ProcessingStatus,
  certificate: Option[CertificateRepositoryObjectValidationContext],
  lastUpdated: Option[DateTime] = None) {
  def name: String = locator.getCaName()
  def prefetchUris: Seq[URI] = locator.getPrefetchUris().asScala
}

class TrustAnchors(val all: Seq[TrustAnchor]) {
  def startProcessing(locator: TrustAnchorLocator, description: String) = {
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator) ta.copy(status = Running(description))
      else ta
    })
  }
  def finishedProcessing(locator: TrustAnchorLocator, result: Validation[String, CertificateRepositoryObjectValidationContext]): TrustAnchors = {
    val now = new DateTime
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator) {
        result match {
          case Success(certificate) =>
            val nextUpdate = now.plusHours(4)
            ta.copy(lastUpdated = Some(now), status = Idle(nextUpdate), certificate = Some(certificate))
          case Failure(errorMessage) =>
            val nextUpdate = now.plusHours(1)
            ta.copy(lastUpdated = Some(now), status = Idle(nextUpdate, Some(errorMessage)))
        }
      } else ta
    })
  }
}

object TrustAnchors extends Logging {
  def load(files: Seq[File], outputDirectory: String): TrustAnchors = {
    val now = new DateTime
    info("Loading trust anchors...")
    val trustAnchors = for (file <- files) yield {
      val tal = TrustAnchorLocator.fromFile(file)
      new TrustAnchor(
        locator = tal,
        status = Idle(now),
        certificate = None)
    }
    new TrustAnchors(trustAnchors)
  }
}
