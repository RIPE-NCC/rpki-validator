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

import models.TrustAnchors
import grizzled.slf4j.Logging
import org.apache.commons.io.FileUtils
import java.io.File
import scala.collection.JavaConverters._
import net.ripe.rpki.validator.models.TrustAnchorValidationProcess
import net.ripe.rpki.validator.models.MeasureValidationProcess
import net.ripe.rpki.validator.models.MeasureRsyncExecution
import scalaz.Failure
import net.ripe.rpki.validator.models.MeasureInconsistentRepositories
import net.ripe.rpki.validator.models.TrackValidationProcess
import net.ripe.rpki.validator.models.ValidationProcessLogger
import net.ripe.rpki.validator.models.ValidationProcess
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import java.net.URI
import net.ripe.rpki.validator.models.ValidatedObject
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.ValidationLocation
import net.ripe.certification.validator.commands.TopDownWalker
import net.ripe.rpki.validator.store.RepositoryObjectStore
import net.ripe.rpki.validator.store.DataSources._
import org.joda.time.DateTime
import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.rpki.validator.store.RepositoryObjectStore
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher
import net.ripe.commons.certification.rsync.Rsync
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
import net.ripe.certification.validator.util.UriToFileMapper
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import net.ripe.rpki.validator.fetchers.HttpObjectFetcher
import net.ripe.rpki.validator.fetchers.RemoteObjectFetcher
import net.ripe.rpki.validator.fetchers.ConsistentObjectFetcher
import net.ripe.certification.validator.fetchers.ValidatingCertificateRepositoryObjectFetcher
import net.ripe.certification.validator.fetchers.CachingCertificateRepositoryObjectFetcher
import org.joda.time.Duration

object BenchmarkMain {

  def main(args: Array[String]): Unit = BenchmarkOptions.parse(args) match {
    case Right(options) =>
      new BenchmarkMain(options)
    case Left(message) =>
      println(message)
      sys.exit(1)
  }
}

class BenchmarkMain(options: BenchmarkOptions) extends Logging {

  val trustAnchor = loadTrustAnchors().all.head // Get the first TA, TODO, support more?
  val httpPreferred = false // TODO get from options
  val runs = 1 to 10 // TODO: Get this from options

  for (runNumber <- runs) {
    info("Starting validation process for run " + runNumber)
    val repositoryObjectStore = new RepositoryObjectStore(InMemoryDataSource) // TODO dedicated store when doing concurrent validations

    val process = new BenchmarkValidationProcess(trustAnchorLocator = trustAnchor.locator, httpSupport = httpPreferred, repositoryObjectStore = repositoryObjectStore)
    val benchmarks = process.run

    info("Found benchmarks: " + benchmarks.toCsvLine(trustAnchor.name))
    info("Writing these benchmarks to statsfile")

    BenchmarkStatistics.save(trustAnchor.name, benchmarks)
  }

  private def loadTrustAnchors(): TrustAnchors = {
    import java.{ util => ju }
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/benchmark-tal"), Array("tal"), false).asInstanceOf[ju.Collection[File]])
    TrustAnchors.load(tals.asScala, "tmp/benchmark-tals")
  }
}
