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
package benchmark

import store.RepositoryObjectStore
import fetchers._
import store.DataSources.DurableDataSource
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.certification.validator.fetchers._
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
import net.ripe.certification.validator.util.UriToFileMapper
import net.ripe.certification.validator.util.TrustAnchorExtractor
import net.ripe.certification.validator.commands.TopDownWalker
import net.ripe.commons.certification.rsync.Rsync
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.ValidationLocation
import scala.collection.JavaConverters._
import grizzled.slf4j.Logging
import java.io.File
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import org.joda.time.DateTimeUtils
import java.net.URI
import net.ripe.rpki.validator.models.ValidatedObject

class BenchmarkValidationProcess(trustAnchorLocator: TrustAnchorLocator, httpSupport: Boolean, repositoryObjectStore: RepositoryObjectStore, cacheDirectory: String, rootCertificateOutputDir: String) extends Logging {

  def run() = {
    val taContext = new TrustAnchorExtractor().extractTA(trustAnchorLocator, rootCertificateOutputDir)

    val validatedObjectBuilder = Map.newBuilder[URI, ValidatedObject]
    val validatedObjectCollector = new ValidatedObjectCollector(trustAnchorLocator, validatedObjectBuilder)

    val fetcher = createFetcher(listeners = Seq(validatedObjectCollector): _*)

    val timeToPrefetch = time {
      trustAnchorLocator.getPrefetchUris().asScala.foreach { prefetchUri =>
        logger.info("Prefetching '" + prefetchUri + "'")
        val validationResult = new ValidationResult();
        validationResult.setLocation(new ValidationLocation(prefetchUri));
        fetcher.prefetch(prefetchUri, validationResult);
        logger.info("Done prefetching for '" + prefetchUri + "'")
      }
    }

    val timeToValidate = time {
      val walker = new TopDownWalker(fetcher)
      walker.addTrustAnchor(taContext)
      walker.execute()
    }

    val totalObjects = validatedObjectBuilder.result.values.size

    BenchmarkData(timeToPrefetch = timeToPrefetch, timeToValidate = timeToValidate, totalObjects = totalObjects)

  }

  private def time(f: => Unit): Long = {
    val beforeMillis = DateTimeUtils.currentTimeMillis
    f
    val afterMillis = DateTimeUtils.currentTimeMillis
    afterMillis - beforeMillis
  }

  private def createFetcher(listeners: NotifyingCertificateRepositoryObjectFetcher.Listener*): CertificateRepositoryObjectFetcher = {
    val rsync = new Rsync()
    rsync.setTimeoutInSeconds(300)
    val rsyncFetcher = new RsyncCertificateRepositoryObjectFetcher(rsync, new UriToFileMapper(new File(cacheDirectory + trustAnchorLocator.getFile().getName())))
    val httpClient: DefaultHttpClient = new DefaultHttpClient(new ThreadSafeClientConnManager)

    val remoteFetcher = httpSupport match {
      case true =>
        val httpFetcher = new HttpObjectFetcher(httpClient)
        new RemoteObjectFetcher(rsyncFetcher, Some(httpFetcher))
      case false =>
        new RemoteObjectFetcher(rsyncFetcher, None)
    }
    val consistentObjectFercher = new ConsistentObjectFetcher(remoteFetcher, repositoryObjectStore)
    val validatingFetcher = new ValidatingCertificateRepositoryObjectFetcher(consistentObjectFercher)
    val notifyingFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingFetcher)
    val cachingFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingFetcher)
    validatingFetcher.setOuterMostDecorator(cachingFetcher)

    listeners.foreach(notifyingFetcher.addCallback)

    cachingFetcher
  }

}