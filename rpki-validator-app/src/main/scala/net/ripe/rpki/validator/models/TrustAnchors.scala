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
package net.ripe.rpki.validator.models

import java.io.File
import java.net.URI

import grizzled.slf4j.Logging
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.lib.HashSupport
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.DateTime

import scala.collection.JavaConverters._
import scala.math.Ordering.Implicits._
import scalaz.{Failure, Success, Validation}

// Ignore unused warning for implicit def from net.ripe.rpki.validator.lib.DateAndTime._
import net.ripe.rpki.validator.lib.DateAndTime._

sealed trait ProcessingStatus {
  def isIdle: Boolean
  def isRunning: Boolean = !isIdle
}
case class Idle(nextUpdate: DateTime, errorMessage: Option[String] = None) extends ProcessingStatus {
  val isIdle = true
}
case class Running(description: String) extends ProcessingStatus {
  val isIdle = false
}

case class TrustAnchorData(enabled: Boolean = true)

case class TrustAnchor(
  locator: TrustAnchorLocator,
  status: ProcessingStatus,
  enabled: Boolean = true,
  certificate: Option[X509ResourceCertificate] = None,
  manifest: Option[ManifestCms] = None,
  crl: Option[X509Crl] = None,
  lastUpdated: Option[DateTime] = None) {

  def identifierHash: String = HashSupport.createShortHexEncodedHash(locator.toString)

  def name: String = locator.getCaName
  def prefetchUris: Seq[URI] = locator.getPrefetchUris.asScala

  def manifestNextUpdateTime: Option[DateTime] = manifest.map { manifest =>
    manifest.getNextUpdateTime min manifest.getCertificate.getValidityPeriod.getNotValidAfter
  }

  def crlNextUpdateTime: Option[DateTime] = crl.map(_.getNextUpdateTime)

  def finishProcessing(result: Validation[String, Seq[ValidatedObject]]) = {
    val now = new DateTime

    result match {
      case Success(validatedObjects) =>
        val validatedObjectsByUri: Map[URI, ValidatedObject] = validatedObjects.map(vo => vo.uri -> vo)(collection.breakOut)
        val nextUpdate = now.plus(ApplicationOptions.validationInterval.toMillis)
        val trustAnchor = validatedObjectsByUri.get(locator.getFetchedCertificateUri).collect {
          case ValidObject(_, _, _, _, certificate: X509ResourceCertificate) => certificate
        }
        val manifest = trustAnchor.flatMap(ta => validatedObjectsByUri.get(ta.getManifestUri)).collect {
          case ValidObject(_, _, _, _, manifest: ManifestCms) => manifest
        }
        val crl = manifest.flatMap(mft => validatedObjectsByUri.get(mft.getCrlUri)).collect {
          case ValidObject(_, _, _, _, crl: X509Crl) => crl
        }

        copy(lastUpdated = Some(now), status = Idle(nextUpdate), certificate = trustAnchor, manifest = manifest, crl = crl)
      case Failure(errorMessage) =>
        val nextUpdate = now.plusHours(1)
        copy(lastUpdated = Some(now), status = Idle(nextUpdate, Some(errorMessage)))
    }
  }
}

class TrustAnchors(anchors: Seq[TrustAnchor]) {
  val all = anchors.toList
  def startProcessing(locator: TrustAnchorLocator, description: String) = {
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator) ta.copy(status = Running(description))
      else ta
    })
  }
  def finishedProcessing(locator: TrustAnchorLocator, result: Validation[String, Seq[ValidatedObject]]): TrustAnchors = {
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator)
        ta.finishProcessing(result)
      else ta
    })
  }

  def updateTrustAnchorState(locator: TrustAnchorLocator, enabled: Boolean) = {
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator) ta.copy(enabled = enabled)
      else ta
    })
  }

  def hasEnabledAnchors = all.exists(_.enabled)
}

object TrustAnchors extends Logging {
  def load(files: Seq[File]): TrustAnchors = {
    val now = new DateTime
    info("Loading trust anchors...")
    val trustAnchors = files.map { file =>
      val tal = TrustAnchorLocator.fromFile(file)
      TrustAnchor(
        locator = tal,
        status = Idle(now),
        enabled = true,
        certificate = None,
        manifest = None,
        crl = None)
    }
    new TrustAnchors(trustAnchors)
  }
}
