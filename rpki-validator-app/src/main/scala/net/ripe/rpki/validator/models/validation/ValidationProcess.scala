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
package net.ripe.rpki.validator.models.validation

import java.net.URI

import com.google.common.collect.Lists
import grizzled.slf4j.Logger
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateUtil, X509ResourceCertificate}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.validation.{ValidationCheck, ValidationLocation, ValidationOptions, ValidationResult, ValidationStatus, ValidationString}
import net.ripe.rpki.validator.config.{ApplicationOptions, MemoryImage}
import net.ripe.rpki.validator.fetchers.Fetcher.Error
import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher
import net.ripe.rpki.validator.lib.DateAndTime
import net.ripe.rpki.validator.lib.Structures._
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.store.CacheStore
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.Instant

import scala.collection.JavaConverters._
import scala.collection.mutable
import scala.concurrent.stm._
import scalaz.{Failure, Success, Validation}


trait ValidationProcess {
  protected[this] val logger = Logger[ValidationProcess]

  def trustAnchorLocator: TrustAnchorLocator

  def runProcess(forceNewFetch: Boolean): Validation[String, Seq[ValidatedObject]] = {
    try {
      val startTime = Instant.now
      val certificate = extractTrustAnchorLocator(forceNewFetch, startTime)
      certificate match {
        case ValidObject(_, uri, _, checks, trustAnchor: X509ResourceCertificate) =>
          val context = new CertificateRepositoryObjectValidationContext(uri, trustAnchor)
          Success(validateObjects(context, forceNewFetch, startTime) :+ certificate)
        case _ =>
          Success(Seq(certificate))
      }
    } catch {
      exceptionHandler
    } finally {
      finishProcessing()
    }
  }

  def exceptionHandler: PartialFunction[Throwable, Validation[String, Nothing]] = {
    case e: Exception =>
      logger.error("Exception when running validation process", e)
      e.printStackTrace()
      val message = if (e.getMessage != null) e.getMessage else e.toString
      Failure(message)
  }

  def objectFetcherListeners: Seq[NotifyingCertificateRepositoryObjectFetcher.Listener] = Seq.empty

  def extractTrustAnchorLocator(forceNewFetch: Boolean, validationStart: Instant): ValidatedObject
  def validateObjects(certificate: CertificateRepositoryObjectValidationContext, forceNewFetch: Boolean, validationStart: Instant): Seq[ValidatedObject]
  def finishProcessing(): Unit = {}

  def shutdown(): Unit = {}
}

class TrustAnchorValidationProcess(override val trustAnchorLocator: TrustAnchorLocator,
                                   store: CacheStore,
                                   repoService: RepoService,
                                   maxStaleDays: Int,
                                   taName: String,
                                   enableLooseValidation: Boolean = false)
  extends ValidationProcess {

  private val validationOptions = new ValidationOptions()

  validationOptions.setMaxStaleDays(maxStaleDays)
  validationOptions.setLooseValidationEnabled(enableLooseValidation)

  override def extractTrustAnchorLocator(forceNewFetch: Boolean, validationStart: Instant): ValidatedObject = {
    val fetchErrors = mutable.Buffer[Error]()

    val certificateLocations: Seq[URI] = trustAnchorLocator.getCertificateLocations.asScala

    val taCertUri = certificateLocations.find { uri =>
      val errors = repoService.visitTrustAnchorCertificate(uri, forceNewFetch = true, validationStart)
      fetchErrors.appendAll(errors)
      errors.isEmpty
    } getOrElse certificateLocations.head

    trustAnchorLocator.setFetchedCertificateUri(taCertUri)

    val validationResult = ValidationResult.withLocation(taCertUri)

    val fetchErrorChecks = fetchErrors.map(e =>
      new ValidationCheck(ValidationStatus.FETCH_ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_FOUND, e.url.toString, e.message))

    val certificates = store.getCertificates(taCertUri.toString)
    if (certificates.size > 1) {
      validationResult.warnForLocation(
        new ValidationLocation(taCertUri),
        ValidationString.VALIDATOR_REPOSITORY_TA_CERT_URI_NOT_UNIQUE,
        taCertUri.toString)
    }
    val matchingCertificates = certificates.filter(keyInfoMatches)
    if (matchingCertificates.size == 1) {
      validationResult.rejectIfFalse(keyInfoMatches(matchingCertificates.head), ValidationString.TRUST_ANCHOR_PUBLIC_KEY_MATCH)
      store.updateValidationTimestamp(Seq(matchingCertificates.head.hash), validationStart)
    } else {
      if (matchingCertificates.size > 1) {
        validationResult.rejectForLocation(new ValidationLocation(taCertUri),
          ValidationString.VALIDATOR_REPOSITORY_TA_CERT_NOT_UNIQUE,
          taCertUri.toString)
      } else {
        validationResult.rejectForLocation(new ValidationLocation(taCertUri),
          ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE,
          taCertUri.toString,
          "n/a")
      }
    }

    if (validationResult.hasFailureForCurrentLocation)
      ValidatedObject.invalid(None, Lists.newArrayList("No trust anchor certificate"), taCertUri, None,
        (validationResult.getAllValidationChecksForCurrentLocation.asScala ++ fetchErrorChecks).toSet)
    else {
      val taCertificate = matchingCertificates.head
      ValidatedObject.valid(
        Some("cert", taCertificate),
        Lists.newArrayList(taCertificate.decoded.getSubject.getName),
        taCertUri,
        Some(taCertificate.hash),
        (validationResult.getAllValidationChecksForCurrentLocation.asScala ++ fetchErrorChecks).toSet,
        taCertificate.decoded
      )
    }
  }

  override def validateObjects(certificate: CertificateRepositoryObjectValidationContext, forceNewFetch: Boolean, startTime: Instant) = {
    trustAnchorLocator.getPrefetchUris.asScala.foreach(repoService.visitRepo(forceNewFetch, startTime))
    val walker = TopDownWalker.create(certificate, store, repoService, validationOptions, startTime, ApplicationOptions.preferRrdp)
    block(walker.execute(forceNewFetch)) {
      store.clearObjects(startTime)
    }
  }

  def keyInfoMatches(certificate: CertificateObject): Boolean = {
    trustAnchorLocator.getPublicKeyInfo == X509CertificateUtil.getEncodedSubjectPublicKeyInfo(certificate.decoded.getCertificate)
  }
}

trait TrackValidationProcess extends ValidationProcess {
  def memoryImage: Ref[MemoryImage]

  abstract override def runProcess(forceNewFetch: Boolean) = {
    val start = atomic { implicit transaction =>
      (for (
        ta <- memoryImage().trustAnchors.all.find(_.locator == trustAnchorLocator)
        if ta.status.isIdle && ta.enabled
      ) yield {
          memoryImage.transform { _.startProcessingTrustAnchor(ta.locator, "Updating certificate") }
        }).isDefined
    }
    if (start) {
      val result = super.runProcess(forceNewFetch)
      memoryImage.single.transform {
        _.finishedProcessingTrustAnchor(trustAnchorLocator, result)
      }
      result
    } else Failure("Trust anchor not idle or enabled")
  }

  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext, forceNewFetch: Boolean, validationStart: Instant) = {
    memoryImage.single.transform { _.startProcessingTrustAnchor(trustAnchorLocator, "Updating ROAs") }
    super.validateObjects(certificate, forceNewFetch, validationStart)
  }
}

trait ValidationProcessLogger extends ValidationProcess {
  override def objectFetcherListeners = super.objectFetcherListeners :+ ObjectFetcherLogger

  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext, forceNewFetch: Boolean, validationStart: Instant) = {
    logger.info("Loaded trust anchor " + trustAnchorLocator.getCaName + " from location " + certificate.getLocation + ", starting validation")
    val (objects, elapsed) = DateAndTime.timed {
      super.validateObjects(certificate, forceNewFetch, validationStart)
    }
    logger.info(s"Finished validating ${trustAnchorLocator.getCaName}, ${objects.size} valid objects; spent ${elapsed/1000.0}s.")
    objects
  }

  abstract override def exceptionHandler = {
    case e: Exception =>
      logger.error("Error while validating trust anchor " + trustAnchorLocator.getCaName, e)
      super.exceptionHandler(e)
  }

  private object ObjectFetcherLogger extends NotifyingCertificateRepositoryObjectFetcher.ListenerAdapter {
    override def afterPrefetchFailure(uri: URI, result: ValidationResult) {
      logger.warn("Failed to prefetch '" + uri + "'")
    }
    override def afterPrefetchSuccess(uri: URI, result: ValidationResult) {
      logger.debug("Prefetched '" + uri + "'")
    }
    override def afterFetchFailure(uri: URI, result: ValidationResult) {
      logger.warn("Failed to validate '" + uri + "': " + result.getFailuresForCurrentLocation.asScala.map(_.toString).mkString(", "))
    }
    override def afterFetchSuccess(uri: URI, obj: CertificateRepositoryObject, result: ValidationResult) {
      logger.debug("Validated OBJECT '" + uri + "'")
    }
  }
}

