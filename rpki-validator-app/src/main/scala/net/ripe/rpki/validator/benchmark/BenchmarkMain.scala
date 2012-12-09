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

import grizzled.slf4j.Logging
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import net.ripe.rpki.validator.store.DataSources._
import net.ripe.rpki.validator.store.RepositoryObjectStore
import net.ripe.certification.validator.util.TrustAnchorLocator
import org.apache.commons.io.FileUtils
import scala.annotation.tailrec

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
  val trustAnchorLocator = TrustAnchorLocator.fromFile(options.talFile)

  val runCounter = new AtomicInteger(0)

  val threads = for (threadId <- 1 to options.threadCount) yield {
    val thread = new Thread {
      val cacheDirectory = "tmp/cache_" + threadId + "/"
      val rootCertificateOutputDir = "tmp/benchmark-tals_" + threadId

      @tailrec override def run {
        val executionId = runCounter.incrementAndGet
        if (executionId <= options.validationRunCount) {
          runExecution(executionId)
          run
        }
      }

      private def runExecution(executionId: Int) {
        info("Starting validation process for run #" + executionId + " (thread " + threadId + ")")
        val dataSource = inMemoryDataSourceForId(String.valueOf(executionId))
        try {
          val repositoryObjectStore = new RepositoryObjectStore(dataSource)

          val process = new BenchmarkValidationProcess(
            trustAnchorLocator = trustAnchorLocator,
            httpSupport = options.httpSupport,
            repositoryObjectStore = repositoryObjectStore,
            cacheDirectory = cacheDirectory,
            rootCertificateOutputDir = rootCertificateOutputDir)
          val benchmarks = process.run

          info("Found benchmarks: " + benchmarks.toCsvLine(trustAnchorLocator.getCaName))
          info("Writing these benchmarks to statsfile")

          BenchmarkStatistics.save(trustAnchorLocator.getCaName, benchmarks)

        } finally {
          dataSource.close
          FileUtils.deleteDirectory(new File(cacheDirectory))
          FileUtils.deleteDirectory(new File(rootCertificateOutputDir))
        }
      }
    }
    thread.setName("validator-" + threadId)
    thread.start
    thread
  }

  threads.foreach(_.join)

  info("Finished all threads");
}
