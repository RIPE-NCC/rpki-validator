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
import collection.mutable
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.x509cert.X509ResourceCertificate

class BenchmarkValidationProcess(trustAnchorLocator: TrustAnchorLocator, httpSupport: Boolean, repositoryObjectStore: RepositoryObjectStore, cacheDirectory: String, rootCertificateOutputDir: String) extends Logging {

  def run() = {
    val taContext = new TrustAnchorExtractor().extractTA(trustAnchorLocator, rootCertificateOutputDir)

    val validatedObjectBuilder = Map.newBuilder[URI, ValidatedObject]
    val validatedObjectCollector = new ValidatedObjectCollector(trustAnchorLocator, validatedObjectBuilder)

//    val fetcher = createFetcher(listeners = Seq(validatedObjectCollector): _*)
    val fetcher = createSimplifiedFetcher()

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
//      val walker = new TopDownWalker(fetcher)
      val walker = new ConcurrentTopDownWalker(fetcher)
      walker.addTrustAnchor(taContext)
      walker.execute
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

  private def createSimplifiedFetcher(): CertificateRepositoryObjectFetcher = {
    val rsync = new Rsync()
    rsync.setTimeoutInSeconds(300)
    val rsyncFetcher = new RsyncCertificateRepositoryObjectFetcher(rsync, new UriToFileMapper(new File(cacheDirectory + trustAnchorLocator.getFile().getName())))
    val httpClient: DefaultHttpClient = new DefaultHttpClient(new ThreadSafeClientConnManager)

    httpSupport match {
      case true =>
        val httpFetcher = new HttpObjectFetcher(httpClient)
        new RemoteObjectFetcher(rsyncFetcher, Some(httpFetcher))
      case false =>
        new RemoteObjectFetcher(rsyncFetcher, None)
    }
  }
}

class ConcurrentTopDownWalker(certificateRepositoryObjectFetcher: CertificateRepositoryObjectFetcher) {

  val validationResult = new ValidationResult
  val queue = new mutable.Queue[CertificateRepositoryObjectValidationContext]

  def addTrustAnchor(trustAnchor: CertificateRepositoryObjectValidationContext) {
    queue += trustAnchor
  }

  def execute {
    while (!queue.isEmpty) {
      val context = queue.dequeue()
      prefetch(context)
      processManifest(context)
    }
  }

  def prefetch(context: CertificateRepositoryObjectValidationContext) {
    val repositoryURI = context.getRepositoryURI()
    validationResult.setLocation(new ValidationLocation(repositoryURI));
    certificateRepositoryObjectFetcher.prefetch(repositoryURI, validationResult);
  }

  def processManifest(context: CertificateRepositoryObjectValidationContext) {
    val manifestURI = context.getManifestURI()
    val manifestCms = fetchManifest(manifestURI, context)
    if (manifestCms != null) {
      processManifestFiles(context, manifestCms)
    }
  }

  def fetchManifest(manifestURI: URI, context: CertificateRepositoryObjectValidationContext) = {
    validationResult.setLocation(new ValidationLocation(manifestURI))
    certificateRepositoryObjectFetcher.getManifest(manifestURI, context, validationResult)
  }

  def processManifestFiles(context: CertificateRepositoryObjectValidationContext, manifestCms: ManifestCms ) {
    val repositoryURI = context.getRepositoryURI()
    manifestCms.getFileNames.asScala.foreach(filename => processManifestEntry(manifestCms, context, repositoryURI, filename))
  }

  def processManifestEntry(manifestCms: ManifestCms, context: CertificateRepositoryObjectValidationContext, repositoryURI: URI, filename: String) {
    val uri = repositoryURI.resolve(filename)
    validationResult.setLocation(new ValidationLocation(uri))
    val cro = certificateRepositoryObjectFetcher.getObject(uri, context, manifestCms.getFileContentSpecification(filename), validationResult)
    addToWorkQueueIfObjectIssuer(context, uri, cro)
  }

  def addToWorkQueueIfObjectIssuer(context: CertificateRepositoryObjectValidationContext, objectURI: URI, cro: CertificateRepositoryObject) {
    cro match {
      case childCertificate: X509ResourceCertificate =>
        if (childCertificate.isObjectIssuer()) {
          if (queue.contains())
          queue += context.createChildContext(objectURI, childCertificate)
        }
      case _ =>
    }
  }
}
