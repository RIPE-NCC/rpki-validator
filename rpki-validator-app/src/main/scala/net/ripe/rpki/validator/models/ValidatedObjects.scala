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
package net.ripe.rpki.validator
package models

import lib.Java
import scala.collection._
import scala.collection.JavaConverters._
import java.io.File
import java.net.URI
import grizzled.slf4j.Logger
import net.ripe.certification.validator.fetchers._
import net.ripe.certification.validator.util._
import net.ripe.certification.validator.commands.TopDownWalker
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.cms.roa.RoaCms
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.validation.ValidationCheck
import net.ripe.commons.certification.validation.ValidationLocation

sealed trait ValidatedObject {
  val uri: URI
  val checks: Set[ValidationCheck]
  val isValid: Boolean
}

case class InvalidObject(uri: URI, checks: Set[ValidationCheck]) extends ValidatedObject {
  override val isValid = false
}

case class ValidObject(uri: URI, checks: Set[ValidationCheck], repositoryObject: CertificateRepositoryObject) extends ValidatedObject {
  override val isValid = true
}

case class ValidRoa(uri: URI, checks: Set[ValidationCheck], roa: RoaCms) extends ValidatedObject {
  override val isValid = true
}

class ValidatedObjects(val all: Map[String, Seq[ValidatedObject]]) {

  def getValidatedRtrPrefixes = {

    for {
      (trustAnchorName, validatedObjects) <- all
      ValidRoa(_, _, roa) <- validatedObjects
      roaPrefix <- roa.getPrefixes().asScala
    } yield {
      RtrPrefix(roa.getAsn, roaPrefix.getPrefix, Java.toOption(roaPrefix.getMaximumLength), Option(trustAnchorName))
    }
  }

  def update(tal: TrustAnchorLocator, validatedObjects: Seq[ValidatedObject]) = {
    new ValidatedObjects(all.updated(tal.getCaName(), validatedObjects))
  }

}

object ValidatedObjects {
  private val logger = Logger[this.type]

  def apply(trustAnchors: TrustAnchors): ValidatedObjects = {
    new ValidatedObjects(trustAnchors.all.map(ta => ta.locator.getCaName() -> Seq.empty[ValidatedObject])(breakOut))
  }

  def fetchObjects(trustAnchor: TrustAnchorLocator, certificate: CertificateRepositoryObjectValidationContext) = {
    import net.ripe.commons.certification.rsync.Rsync

    val rsync = new Rsync()
    rsync.setTimeoutInSeconds(300)
    val rsyncFetcher = new RsyncCertificateRepositoryObjectFetcher(rsync, new UriToFileMapper(new File("tmp/cache/" + trustAnchor.getFile().getName())))
    val validatingFetcher = new ValidatingCertificateRepositoryObjectFetcher(rsyncFetcher);
    val notifyingFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingFetcher);
    val cachingFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingFetcher);
    validatingFetcher.setOuterMostDecorator(cachingFetcher);

    val builder = Map.newBuilder[URI, ValidatedObject]
    notifyingFetcher.addCallback(new RoaCollector(trustAnchor, builder))

    trustAnchor.getPrefetchUris().asScala.foreach { prefetchUri =>
      logger.info("Prefetching '" + prefetchUri + "'")
      val validationResult = new ValidationResult();
      validationResult.setLocation(new ValidationLocation(prefetchUri));
      cachingFetcher.prefetch(prefetchUri, validationResult);
    }

    val walker = new TopDownWalker(cachingFetcher)
    walker.addTrustAnchor(certificate)
    logger.info("Started validating " + trustAnchor.getCaName())
    walker.execute()

    val objects = builder.result()
    logger.info("Finished validating " + trustAnchor.getCaName() + ", fetched " + objects.size + " valid Objects")

    objects
  }

  private class RoaCollector(trustAnchor: TrustAnchorLocator, objects: collection.mutable.Builder[(URI, ValidatedObject), _]) extends NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback {
    override def afterPrefetchFailure(uri: URI, result: ValidationResult) {
      logger.warn("Failed to prefetch '" + uri + "'")
    }

    override def afterPrefetchSuccess(uri: URI, result: ValidationResult) {
      logger.debug("Prefetched '" + uri + "'")
    }

    override def afterFetchFailure(uri: URI, result: ValidationResult) {
      objects += uri -> new InvalidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet)
      logger.warn("Failed to validate '" + uri + "': " + result.getFailuresForCurrentLocation().asScala.map(_.toString()).mkString(", "))
    }

    override def afterFetchSuccess(uri: URI, obj: CertificateRepositoryObject, result: ValidationResult) {
      obj match {
        case roa: RoaCms =>
          logger.debug("Validated ROA '" + uri + "'")
          objects += uri -> new ValidRoa(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, roa)
        case _ =>
          objects += uri -> new ValidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, obj)
          logger.debug("Validated OBJECT '" + uri + "'")
      }
    }
  }
}
