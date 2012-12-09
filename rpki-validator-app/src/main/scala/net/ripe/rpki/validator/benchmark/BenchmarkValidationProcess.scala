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
import net.ripe.certification.validator.util.{HierarchicalUriCache, TrustAnchorLocator, UriToFileMapper, TrustAnchorExtractor}
import net.ripe.certification.validator.fetchers._
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
import net.ripe.certification.validator.commands.TopDownWalker
import net.ripe.commons.certification.rsync.Rsync
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.ValidationLocation
import scala.collection.JavaConverters._
import grizzled.slf4j.Logging
import java.io.File
import org.apache.http.impl.client.{DefaultRedirectStrategy, DefaultHttpClient}
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import org.joda.time.DateTimeUtils
import java.net.URI
import models.{StoredRepositoryObject, ValidatedObject}
import collection.mutable
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.x509cert.X509ResourceCertificate
import annotation.tailrec
import akka.dispatch.{Await, ExecutionContext, Future}
import java.util.concurrent.{TimeUnit, Executors}
import akka.util.Duration
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory
import org.apache.http.client.methods.{HttpHead, HttpGet}
import org.apache.http.{HttpRequest, HttpResponse, HttpEntity}
import org.apache.http.util.EntityUtils
import org.apache.http.client.RedirectStrategy
import org.apache.http.protocol.HttpContext
import org.apache.http.impl.conn.PoolingClientConnectionManager

class BenchmarkValidationProcess(trustAnchorLocator: TrustAnchorLocator, httpSupport: Boolean, repositoryObjectStore: RepositoryObjectStore, cacheDirectory: String, rootCertificateOutputDir: String) extends Logging {

  val parallelism = 100
  val maxConnPerRoute = parallelism
  val totalConn = 256

  val connectionManager = new PoolingClientConnectionManager
  connectionManager.setDefaultMaxPerRoute(maxConnPerRoute)
  connectionManager.setMaxTotal(totalConn)
  val httpClient: DefaultHttpClient = new DefaultHttpClient(connectionManager)
  httpClient.setRedirectStrategy(new DefaultRedirectStrategy {
    override def isRedirected(request: HttpRequest, response: HttpResponse, context: HttpContext) = false
  })

  def run() = {
    val taContext = new TrustAnchorExtractor().extractTA(trustAnchorLocator, rootCertificateOutputDir)

    val validatedObjectBuilder = Map.newBuilder[URI, ValidatedObject]
    val validatedObjectCollector = new ValidatedObjectCollector(trustAnchorLocator, validatedObjectBuilder)

//    val fetcher = createFetcher(listeners = Seq(validatedObjectCollector): _*)
    val uriCache = new HierarchicalUriCache
    def fetcher = createSimplifiedFetcher(uriCache)

    val timeToPrefetch = time {
//      trustAnchorLocator.getPrefetchUris().asScala.foreach { prefetchUri =>
//        logger.info("Prefetching '" + prefetchUri + "'")
//        val validationResult = new ValidationResult();
//        validationResult.setLocation(new ValidationLocation(prefetchUri));
//        fetcher.prefetch(prefetchUri, validationResult);
//        logger.info("Done prefetching for '" + prefetchUri + "'")
//      }
    }

//    val timeToValidate = time {
////      val walker = new TopDownWalker(fetcher)
//      val walker = new ConcurrentTopDownWalker(taContext, fetcher, repositoryObjectStore)
//      walker.execute
//    }
    val uris = repositoryObjectStore.getAllManifestUris.filter(_.toString.startsWith("rsync://certtest-1.local/repository/")).map {
      _.toString.replace("rsync://certtest-1.local/repository/", "http://certtest-1.local/certification/repository/")
    }
    val urisWithDateModified = uris.par.map { uri =>
      val httpHead = new HttpHead(uri)
      val response = httpClient.execute(httpHead)
      (uri -> response.getLastHeader("Last-Modified").getValue)
    }.seq

    def timeToValidate(latency: Long)(implicit executionContext: ExecutionContext) = time {
      val manifests = Future.traverse(urisWithDateModified) { case (uri, dateModified) =>
        Future {
          val httpHead = new HttpHead(uri)
          val response = httpClient.execute(httpHead)
//          val request = new HttpGet(uri)
//          request.addHeader("If-Modified-Since", dateModified)
//          val response: HttpResponse = httpClient.execute(request)
          EntityUtils.consume(response.getEntity)

          if (response.getStatusLine.getStatusCode != 200) {
            println("Weird! Got status code " + response.getStatusLine.getStatusCode + " for URI " + uri)
          }

          Thread.sleep(latency)
//          val context = new CertificateRepositoryObjectValidationContext(uri, null, null)
//          val validationResult = new ValidationResult
//          validationResult.setLocation(new ValidationLocation(uri))
//          fetcher.getManifest(uri, context, validationResult)
        }
      }

      Await.result(manifests, Duration(1, TimeUnit.HOURS))
    }

    for (latency <- Seq(0, 5, 10, 25, 50, 100); concurrency <- 4 to 100 by 4) {
      implicit val executionContext = ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(concurrency))
      println("%d,%d,%.3f" format (latency, concurrency, timeToValidate(latency) / 1000.0))
      executionContext.shutdown()
    }

    connectionManager.shutdown()

//    val totalObjects = validatedObjectBuilder.result.values.size
//
//    BenchmarkData(timeToPrefetch = timeToPrefetch, timeToValidate = timeToValidate, totalObjects = totalObjects)

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

  private def createSimplifiedFetcher(uriCache: HierarchicalUriCache): CertificateRepositoryObjectFetcher = {
    val rsync = new Rsync()
    rsync.setTimeoutInSeconds(300)
    val rsyncFetcher = new RsyncCertificateRepositoryObjectFetcher(rsync, new UriToFileMapper(new File(cacheDirectory + trustAnchorLocator.getFile().getName())), uriCache)

    httpSupport match {
      case true =>
        val httpFetcher = new HttpObjectFetcher(httpClient)
        new RemoteObjectFetcher(rsyncFetcher, Some(httpFetcher))
      case false =>
        new RemoteObjectFetcher(rsyncFetcher, None)
    }
  }
}

class ConcurrentTopDownWalker(trustAnchor: CertificateRepositoryObjectValidationContext,
                              certificateRepositoryObjectFetcher: => CertificateRepositoryObjectFetcher,
                               store: RepositoryObjectStore)(implicit executionContext: ExecutionContext) {

  def newValidationResult(location: URI) = {
    val result = new ValidationResult
    result.setLocation(new ValidationLocation(location))
    result
  }

  def execute {
    def loop(alreadyFetched: Set[URI], context: CertificateRepositoryObjectValidationContext): Future[Int] = {
      for {
        childCerts <- { prefetch(context); processManifest(alreadyFetched, context) }
        childObjects <- Future.traverse(childCerts) { child =>
          loop(alreadyFetched + context.getLocation, child)
        }
      } yield {
        childCerts.size + childObjects.sum
      }
    }
    val total = Await.result(loop(Set(trustAnchor.getLocation), trustAnchor), Duration.apply(1, TimeUnit.HOURS))
    println("Found " + total + " objects")
  }

  def prefetch(context: CertificateRepositoryObjectValidationContext) {
    val repositoryURI = context.getRepositoryURI()
    certificateRepositoryObjectFetcher.prefetch(repositoryURI, newValidationResult(repositoryURI))
  }

  def processManifest(alreadyFetched: Set[URI], context: CertificateRepositoryObjectValidationContext): Future[Seq[CertificateRepositoryObjectValidationContext]] = {
    val manifestURI = context.getManifestURI()
    fetchManifest(manifestURI, context).flatMap { manifestCms =>
    if (manifestCms == null) Future(Vector.empty) else {
      store.put(StoredRepositoryObject(manifestURI, manifestCms))
      val futures = manifestCms.getFileNames.asScala.toIndexedSeq[String].filter { filename =>
        val uri = manifestURI.resolve(filename)
        filename.endsWith("cer") && !(alreadyFetched contains uri)
      }.map { filename =>
         processManifestEntry(manifestCms, context, filename)
      }
      val sequenced = Future.sequence(futures)
      sequenced.map(_.flatten)
    }
    }
  }

  def fetchManifest(manifestURI: URI, context: CertificateRepositoryObjectValidationContext) = {
    Future(certificateRepositoryObjectFetcher.getManifest(manifestURI, context, newValidationResult(manifestURI)))
  }

  def processManifestEntry(manifestCms: ManifestCms, context: CertificateRepositoryObjectValidationContext, filename: String): Future[Option[CertificateRepositoryObjectValidationContext]] = Future {
    val uri = context.getRepositoryURI().resolve(filename)
    val hash = manifestCms.getHash(filename)
    val storedObject = store.getByHash(hash)
    val cmsObject = storedObject match {
      case Some(obj) =>
        CertificateRepositoryObjectFactory.createCertificateRepositoryObject(obj.binaryObject.toArray)
      case None =>
        val obj = certificateRepositoryObjectFetcher.getObject(uri, context, manifestCms.getFileContentSpecification(filename), newValidationResult(uri))
        store.put(StoredRepositoryObject(uri, obj))
        obj
    }
    cmsObject match {
      case childCertificate: X509ResourceCertificate =>
        if (childCertificate.isObjectIssuer()) {
          Some(context.createChildContext(uri, childCertificate))
        } else None
      case _ => None
    }
  }
}
