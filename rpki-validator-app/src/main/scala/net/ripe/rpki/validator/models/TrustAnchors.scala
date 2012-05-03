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

import scala.collection.JavaConverters._
import java.io.File
import java.net.URI
import grizzled.slf4j.Logging
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.certification.validator.util.TrustAnchorLocator
import org.joda.time.DateTime
import scalaz.{ Validation, Failure, Success }
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.rpki.validator.lib.DateAndTime._
import net.ripe.certification.validator.util.TrustAnchorExtractor
import net.ripe.commons.certification.validation.ValidationOptions
import net.ripe.rpki.validator.statistics.Metric
import org.joda.time.DateTimeUtils
import scala.concurrent.stm._
import net.ripe.rpki.validator.config.MemoryImage

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

case class TrustAnchorData(enabled: Boolean = true)

case class TrustAnchor(
    locator: TrustAnchorLocator,
    status: ProcessingStatus,
    enabled: Boolean = true,
    certificate: Option[CertificateRepositoryObjectValidationContext] = None,
    manifest: Option[ManifestCms] = None,
    crl: Option[X509Crl] = None,
    lastUpdated: Option[DateTime] = None) {
  def name: String = locator.getCaName()
  def prefetchUris: Seq[URI] = locator.getPrefetchUris().asScala

  def manifestNextUpdateTime: Option[DateTime] = manifest.map { manifest =>
    manifest.getNextUpdateTime min manifest.getCertificate.getValidityPeriod.getNotValidAfter
  }

  def crlNextUpdateTime: Option[DateTime] = crl.map(_.getNextUpdateTime)

  def finishProcessing(result: Validation[String, (CertificateRepositoryObjectValidationContext, Map[URI, ValidatedObject])]) = {
    val now = new DateTime

    result match {
      case Success((certificate, validatedObjects)) =>
        val nextUpdate = now.plusHours(4)
        val manifest = validatedObjects.get(certificate.getManifestURI).collect {
          case ValidObject(_, _, manifest: ManifestCms) => manifest
        }
        val crl = for {
          mft <- manifest
          crlUri <- Option(mft.getCrlUri)
          ValidObject(_, _, crl: X509Crl) <- validatedObjects.get(crlUri)
        } yield crl

        copy(lastUpdated = Some(now), status = Idle(nextUpdate), certificate = Some(certificate), manifest = manifest, crl = crl)
      case Failure(errorMessage) =>
        val nextUpdate = now.plusHours(1)
        copy(lastUpdated = Some(now), status = Idle(nextUpdate, Some(errorMessage)))
    }
  }
}

class TrustAnchors(val all: Seq[TrustAnchor]) {
  def startProcessing(locator: TrustAnchorLocator, description: String) = {
    new TrustAnchors(all.map { ta =>
      if (ta.locator == locator) ta.copy(status = Running(description))
      else ta
    })
  }
  def finishedProcessing(locator: TrustAnchorLocator, result: Validation[String, (CertificateRepositoryObjectValidationContext, Map[URI, ValidatedObject])]): TrustAnchors = {
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
        enabled = true,
        certificate = None,
        manifest = None,
        crl = None)
    }
    new TrustAnchors(trustAnchors)
  }
}

trait ValidationProcess {
  def trustAnchorLocator: TrustAnchorLocator

  def runProcess(): Validation[String, Map[URI, ValidatedObject]] = {
    try {
      val certificate = extractTrustAnchorLocator()
      Success(validateObjects(certificate))
    } catch {
      exceptionHandler
    } finally {
      finishProcessing()
    }
  }

  def extractTrustAnchorLocator(): CertificateRepositoryObjectValidationContext
  def validateObjects(certificate: CertificateRepositoryObjectValidationContext): Map[URI, ValidatedObject]
  def exceptionHandler: PartialFunction[Throwable, Validation[String, Nothing]]
  def finishProcessing(): Unit = {}
}

abstract class TrustAnchorValidationProcess(override val trustAnchorLocator: TrustAnchorLocator, maxStaleDays: Int) extends ValidationProcess {
  override def extractTrustAnchorLocator() = new TrustAnchorExtractor().extractTA(trustAnchorLocator, "tmp/tals")
  override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    val options = new ValidationOptions()
    options.setMaxStaleDays(maxStaleDays)
    ValidatedObjects.fetchObjects(trustAnchorLocator, certificate, options)
  }
}

trait TrackValidationProcess extends ValidationProcess {
  def memoryImage: Ref[MemoryImage]

  abstract override def runProcess() = {
    val start = atomic { implicit transaction =>
      (for (
        ta <- memoryImage().trustAnchors.all.find(_.locator == trustAnchorLocator);
        if ta.status.isIdle && ta.enabled
      ) yield {
        memoryImage.transform { _.startProcessingTrustAnchor(ta.locator, "Updating certificate") }
      }).isDefined
    }
    if (start) super.runProcess()
    else Failure("Trust anchor not idle or enabled")
  }
  abstract override def extractTrustAnchorLocator() = {
    super.extractTrustAnchorLocator()
  }
  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    memoryImage.single.transform { _.startProcessingTrustAnchor(trustAnchorLocator, "Updating ROAs") }
    val validatedObjects = super.validateObjects(certificate)
    memoryImage.single.transform {
      _.finishedProcessingTrustAnchor(trustAnchorLocator, Success((certificate, validatedObjects)))
    }
    validatedObjects
  }
  abstract override def finishProcessing() = {
    super.finishProcessing()
    // update memory image
  }
  override def exceptionHandler = {
    case e: Exception =>
      val message = if (e.getMessage != null) e.getMessage else e.toString
      memoryImage.single.transform {
        _.finishedProcessingTrustAnchor(trustAnchorLocator, Failure(message))
      }
      Failure(message)
  }
}

trait MeasureValidationProcess extends ValidationProcess {
  private[this] val metricsBuilder = Vector.newBuilder[Metric]
  private[this] val startedAt = DateTimeUtils.currentTimeMillis

  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    metricsBuilder += Metric("trust.anchor[%s].extracted.elapsed.ms" format trustAnchorLocator.getCertificateLocation, (DateTimeUtils.currentTimeMillis - startedAt).toString, DateTimeUtils.currentTimeMillis)
    val result = super.validateObjects(certificate)
    metricsBuilder += Metric("trust.anchor[%s].validation" format trustAnchorLocator.getCertificateLocation, "OK", DateTimeUtils.currentTimeMillis)
    result
  }

  abstract override def finishProcessing() = {
    super.finishProcessing()
    val stop = DateTimeUtils.currentTimeMillis
    metricsBuilder += Metric("trust.anchor[%s].validation.elapsed.ms" format trustAnchorLocator.getCertificateLocation, (stop - startedAt).toString, DateTimeUtils.currentTimeMillis)
  }
  abstract override def exceptionHandler = {
    case e: Exception =>
      metricsBuilder += Metric("trust.anchor[%s].validation" format trustAnchorLocator.getCertificateLocation, "failed: " + e, DateTimeUtils.currentTimeMillis)
      super.exceptionHandler(e)
  }

  lazy val metrics = metricsBuilder.result
}

trait ValidationProcessLogger extends ValidationProcess with Logging {
  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    info("Loaded trust anchor from location " + certificate.getLocation())
    super.validateObjects(certificate)
  }
  abstract override def exceptionHandler = {
    case e: Exception =>
      error("Error while validating trust anchor " + trustAnchorLocator.getCertificateLocation() + ": " + e, e)
      super.exceptionHandler(e)
  }
}
