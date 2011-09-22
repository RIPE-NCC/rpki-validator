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
package net.ripe.rpki.validator
package models

import akka.dispatch.Future
import java.io.File
import java.net.URI
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.certification.validator.fetchers._
import net.ripe.certification.validator.util._
import net.ripe.certification.validator.commands.TopDownWalker
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.cms.roa.RoaCms
import grizzled.slf4j.Logging

class Roas(val all: Map[String, Future[Seq[RoaCms]]]) {

}
object Roas extends Logging {
  def fetch(trustAnchors: TrustAnchors): Roas = {
    val all = for (ta <- trustAnchors.all) yield ta.name -> ta.certificate.flatMap(certificate => fetchObjects(ta.name, ta.prefetchUri, certificate))
    new Roas(all.toMap)
  }

  private def fetchObjects(name: String, prefetchUri: Option[URI], ta: CertificateRepositoryObjectValidationContext): Future[Seq[RoaCms]] = Future({
    import net.ripe.commons.certification.rsync.Rsync

    val rsyncFetcher = new RsyncCertificateRepositoryObjectFetcher(new Rsync(), new UriToFileMapper(new File("tmp/cache/" + name)));
    val validatingFetcher = new ValidatingCertificateRepositoryObjectFetcher(rsyncFetcher);
    val notifyingFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingFetcher);

    val roas = collection.mutable.ArrayBuffer.empty[RoaCms]
    notifyingFetcher.addCallback(new NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback {
      override def afterPrefetchFailure(uri: URI, result: ValidationResult) {
        warn("Failed to prefetch '" + uri + "'")
      }

      override def afterPrefetchSuccess(uri: URI, result: ValidationResult) {
        debug("Prefetched '" + uri + "'")
      }

      override def afterFetchFailure(uri: URI, result: ValidationResult) {
        warn("Failed to fetch '" + uri + "'")
      }

      override def afterFetchSuccess(uri: URI, obj: CertificateRepositoryObject, result: ValidationResult) {
        obj match {
          case roa: RoaCms =>
            info("Fetched ROA '" + uri + "'")
            roas += roa
          case _ =>
            debug("Fetched '" + uri + "'")
        }
      }
    });

    val cachingFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingFetcher);
    validatingFetcher.setOuterMostDecorator(cachingFetcher);

    prefetchUri.foreach { prefetchUri =>
      info("Prefetching '" + prefetchUri + "'")
      val validationResult = new ValidationResult();
      validationResult.setLocation(prefetchUri);
      cachingFetcher.prefetch(prefetchUri, validationResult);
    }

    val walker = new TopDownWalker(cachingFetcher)
    walker.addTrustAnchor(ta)
    info("Start validating " + name)
    walker.execute()
    info("Finished validating " + name)

    roas.toIndexedSeq
  }, timeout = 60 * 60 * 1000)
}
