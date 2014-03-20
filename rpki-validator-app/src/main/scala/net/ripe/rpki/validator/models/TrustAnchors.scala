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
import scala.collection.JavaConverters._
import scala.concurrent.stm.Ref
import scala.concurrent.stm.atomic
import scala.math.Ordering.Implicits._
import org.joda.time.DateTime
import grizzled.slf4j.Logger
import grizzled.slf4j.Logging
import net.ripe.rpki.validator.commands.TopDownWalker
import net.ripe.rpki.validator.util.TrustAnchorLocator
import net.ripe.rpki.validator.util.UriToFileMapper
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.commons.validation.ValidationLocation
import net.ripe.rpki.commons.validation.ValidationOptions
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.validation.ValidationString
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.validator.config.MemoryImage
import net.ripe.rpki.validator.fetchers._
import net.ripe.rpki.validator.lib.HashSupport

// Ignore unused warning for implicit def from net.ripe.rpki.validator.lib.DateAndTime._
import net.ripe.rpki.validator.lib.DateAndTime._
import net.ripe.rpki.validator.store.DataSources
import net.ripe.rpki.validator.store.RepositoryObjectStore
import scalaz._
import org.apache.commons.io.FileUtils

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
  certificate: Option[X509ResourceCertificate] = None,
  manifest: Option[ManifestCms] = None,
  crl: Option[X509Crl] = None,
  lastUpdated: Option[DateTime] = None) {

  def identifierHash: String = HashSupport.createShortHexEncodedHash(locator.getPublicKeyInfo)

  def name: String = locator.getCaName
  def prefetchUris: Seq[URI] = locator.getPrefetchUris.asScala

  def manifestNextUpdateTime: Option[DateTime] = manifest.map { manifest =>
    manifest.getNextUpdateTime min manifest.getCertificate.getValidityPeriod.getNotValidAfter
  }

  def crlNextUpdateTime: Option[DateTime] = crl.map(_.getNextUpdateTime)

  def finishProcessing(result: Validation[String, Map[URI, ValidatedObject]]) = {
    val now = new DateTime

    result match {
      case Success(validatedObjects) =>
        val nextUpdate = now.plusHours(4)
        val trustAnchor = validatedObjects.get(locator.getCertificateLocation).collect {
          case ValidObject(_, _, certificate: X509ResourceCertificate) => certificate
        }
        val manifest = trustAnchor.flatMap(ta => validatedObjects.get(ta.getManifestUri)).collect {
          case ValidObject(_, _, manifest: ManifestCms) => manifest
        }
        val crl = manifest.flatMap(mft => validatedObjects.get(mft.getCrlUri)).collect {
          case ValidObject(_, _, crl: X509Crl) => crl
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
  def finishedProcessing(locator: TrustAnchorLocator, result: Validation[String, Map[URI, ValidatedObject]]): TrustAnchors = {
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
  def load(files: Seq[File]): TrustAnchors = {
    val now = new DateTime
    info("Loading trust anchors...")
    val trustAnchors = files.map { file =>
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
  protected[this] val logger = Logger[ValidationProcess]

  def trustAnchorLocator: TrustAnchorLocator

  def runProcess(): Validation[String, Map[URI, ValidatedObject]] = {
    try {
      val certificate = extractTrustAnchorLocator()
      certificate match {
        case ValidObject(uri, checks, trustAnchor: X509ResourceCertificate) =>
          val context = new CertificateRepositoryObjectValidationContext(uri, trustAnchor)
          Success(validateObjects(context) + (uri -> certificate))
        case _ =>
          Success(Map(certificate.uri -> certificate))
      }
    } catch {
      exceptionHandler
    } finally {
      finishProcessing()
    }
  }

  def exceptionHandler: PartialFunction[Throwable, Validation[String, Nothing]] = {
    case e: Exception =>
      val message = if (e.getMessage != null) e.getMessage else e.toString
      Failure(message)
  }

  def objectFetcherListeners: Seq[NotifyingCertificateRepositoryObjectFetcher.Listener] = Seq.empty

  def extractTrustAnchorLocator(): ValidatedObject
  def validateObjects(certificate: CertificateRepositoryObjectValidationContext): Map[URI, ValidatedObject]
  def finishProcessing(): Unit = {}

  def shutdown(): Unit = {}
}

class TrustAnchorValidationProcess(override val trustAnchorLocator: TrustAnchorLocator, maxStaleDays: Int, workingDirectory: File) extends ValidationProcess {

  private val validationOptions = new ValidationOptions()
  private val RsyncDiskCacheBasePath = workingDirectory.toString + File.separator + "cache" + File.separator
  private val RepositoryObjectStore = DataSources.DurableDataSource(workingDirectory)

  validationOptions.setMaxStaleDays(maxStaleDays)

  override def extractTrustAnchorLocator() = {
    val uri = trustAnchorLocator.getCertificateLocation

    val validationResult = ValidationResult.withLocation(uri)

    consistentObjectFetcher.getTrustAnchorCertificate(uri, validationResult) match {
      case Some(certificate) =>
        validationResult.rejectIfFalse(trustAnchorLocator.getPublicKeyInfo == X509CertificateUtil.getEncodedSubjectPublicKeyInfo(certificate.getCertificate), ValidationString.TRUST_ANCHOR_PUBLIC_KEY_MATCH)
        if (validationResult.hasFailureForCurrentLocation) {
          InvalidObject(uri, validationResult.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet)
        } else {
          ValidObject(uri, validationResult.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, certificate)
        }
      case None =>
        InvalidObject(uri, validationResult.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet)
    }
  }

  override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    val builder = Map.newBuilder[URI, ValidatedObject]
    val fetcher = createFetcher(new RoaCollector(trustAnchorLocator, builder) +: objectFetcherListeners: _*)

    // purge cache
    val cache = new RepositoryObjectStore(RepositoryObjectStore)
    cache.purgeExpired(maxStaleDays)

    trustAnchorLocator.getPrefetchUris.asScala.foreach { prefetchUri =>

      logger.info("Prefetching '" + prefetchUri + "'")
      val validationResult = ValidationResult.withLocation(prefetchUri)

      fetcher.prefetch(prefetchUri, validationResult)
      logger.info("Done prefetching for '" + prefetchUri + "'")
    }

    val walker = new TopDownWalker(fetcher)
    walker.addTrustAnchor(certificate)
    walker.execute()

    builder.result()
  }

  def wipeRsyncDiskCache() {
    val diskCache = new File(RsyncDiskCacheBasePath)
    if (diskCache.isDirectory) {
      FileUtils.cleanDirectory(diskCache)
    }
  }

  private def createFetcher(listeners: NotifyingCertificateRepositoryObjectFetcher.Listener*): CertificateRepositoryObjectFetcher = {
    val validatingFetcher = new ValidatingCertificateRepositoryObjectFetcher(consistentObjectFetcher, validationOptions)
    val notifyingFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingFetcher)
    val cachingFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingFetcher)
    validatingFetcher.setOuterMostDecorator(cachingFetcher)

    listeners.foreach(notifyingFetcher.addCallback)

    cachingFetcher
  }

  private[this] lazy val consistentObjectFetcher = {
    val rsync = new Rsync()
    rsync.setTimeoutInSeconds(300)
    val rsyncFetcher = new RsyncRpkiRepositoryObjectFetcher(rsync, new UriToFileMapper(new File(RsyncDiskCacheBasePath  + trustAnchorLocator.getFile.getName)))
    new ConsistentObjectFetcher(rsyncFetcher, new RepositoryObjectStore(RepositoryObjectStore))
  }

  private class RoaCollector(trustAnchor: TrustAnchorLocator, objects: collection.mutable.Builder[(URI, ValidatedObject), _]) extends NotifyingCertificateRepositoryObjectFetcher.ListenerAdapter {
    override def afterFetchFailure(uri: URI, result: ValidationResult) {
      objects += uri -> new InvalidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet)
    }

    override def afterFetchSuccess(uri: URI, obj: CertificateRepositoryObject, result: ValidationResult) {
      objects += uri -> new ValidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, obj)
    }
  }
}

trait TrackValidationProcess extends ValidationProcess {
  def memoryImage: Ref[MemoryImage]

  abstract override def runProcess() = {
    val start = atomic { implicit transaction =>
      (for (
        ta <- memoryImage().trustAnchors.all.find(_.locator == trustAnchorLocator)
        if ta.status.isIdle && ta.enabled
      ) yield {
        memoryImage.transform { _.startProcessingTrustAnchor(ta.locator, "Updating certificate") }
      }).isDefined
    }
    if (start) {
      val result = super.runProcess()
      memoryImage.single.transform {
        _.finishedProcessingTrustAnchor(trustAnchorLocator, result)
      }
      result
    } else Failure("Trust anchor not idle or enabled")
  }

  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    memoryImage.single.transform { _.startProcessingTrustAnchor(trustAnchorLocator, "Updating ROAs") }
    super.validateObjects(certificate)
  }
}

trait ValidationProcessLogger extends ValidationProcess {
  override def objectFetcherListeners = super.objectFetcherListeners :+ ObjectFetcherLogger

  abstract override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = {
    logger.info("Loaded trust anchor " + trustAnchorLocator.getCaName + " from location " + certificate.getLocation + ", starting validation")
    val objects = super.validateObjects(certificate)
    logger.info("Finished validating " + trustAnchorLocator.getCaName + ", fetched " + objects.size + " valid Objects")
    objects
  }

  abstract override def exceptionHandler = {
    case e: Exception =>
      logger.error("Error while validating trust anchor " + trustAnchorLocator.getCaName + ": " + e.getStackTraceString, e)
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
