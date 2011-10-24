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
package config

import java.io.File
import scala.collection.JavaConverters._
import scala.concurrent.TaskRunners
import scala.concurrent.ops._
import org.apache.commons.io.FileUtils
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet._
import grizzled.slf4j.Logger
import org.joda.time.DateTime
import scalaz.concurrent.Promise

import net.ripe.certification.validator.util.TrustAnchorExtractor
import rtr.Pdu
import rtr.RTRServer
import lib._
import DateAndTime._
import models._
import bgp.preview._

object Main {

  val logger = Logger[this.type]

  private val nonce: Pdu.Nonce = Pdu.randomNonce()

  private var memoryImage: Atomic[MemoryImage] = null
  private var memoryImageListener = Set.empty[MemoryImage => Unit]

  def main(args: Array[String]): Unit = Options.parse(args) match {
    case Right(options) => run(options)
    case Left(message) => error(message)
  }

  private def run(options: Options): Unit = {
    val trustAnchors = loadTrustAnchors()
    val roas = Roas(trustAnchors)
    val dataFile = new File(options.dataFileName).getCanonicalFile()
    val data = PersistentDataSerialiser.read(dataFile).getOrElse(PersistentData(whitelist = Whitelist()))
    memoryImage = new Atomic(
      MemoryImage(data.filters, data.whitelist, trustAnchors, roas),
      memoryImage => for (listener <- memoryImageListener) listener(memoryImage))

    registerMemoryImageListener((memoryImage => BgpAnnouncementValidator.updateRtrPrefixes(memoryImage.getDistinctRtrPrefixes())))
    scheduleValidator()
    runWebServer(options, dataFile)
    runRtrServer(options)
  }

  private def error(message: String) = {
    println(message)
    sys.exit(1)
  }

  def loadTrustAnchors(): TrustAnchors = {
    import java.{ util => ju }
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/tal"), Array("tal"), false).asInstanceOf[ju.Collection[File]])
    TrustAnchors.load(tals.asScala, "tmp/tals")
  }

  private def scheduleValidator() {
    implicit val runner = TaskRunners.threadRunner
    spawn {
      try {
        Thread.currentThread().setName("validator-scheduler")
        logger.info("Started validation scheduler")

        while (!Thread.currentThread().isInterrupted()) {
          val trustAnchors = memoryImage.get.trustAnchors
          val now = new DateTime
          val needUpdating = for {
            ta <- trustAnchors.all if ta.status.isIdle
            Idle(nextUpdate) = ta.status if nextUpdate <= now
          } yield ta

          runValidator(needUpdating)
          logger.debug("Validation scheduler is sleeping...")
          Thread.sleep(10000L)
        }

        logger.info("Validation scheduler terminating")
      } catch {
        case e: Exception =>
          logger.error("Exception in validator scheduler, terminating", e)
          throw e
      }
    }
  }

  def runValidator(trustAnchors: Seq[TrustAnchor]) {
    implicit val runner = TaskRunners.threadPoolRunner
    for (ta <- trustAnchors; Idle(_) = ta.status) {
      memoryImage.update { _.startProcessingTrustAnchor(ta.locator, "Updating certificate") }
      spawn {
        val certificate = new TrustAnchorExtractor().extractTA(ta.locator, "tmp/tals")
        logger.info("Loaded trust anchor from location " + certificate.getLocation())
        memoryImage.update { _.startProcessingTrustAnchor(ta.locator, "Updating ROAs") }

        val validatedRoas = Roas.fetchObjects(ta.locator, certificate)
        memoryImage.update {
          _.updateRoas(ta.locator, validatedRoas).finishedProcessingTrustAnchor(ta.locator, certificate)
        }
      }
    }
  }

  def setup(server: Server, dataFile: File): Server = {
    import org.eclipse.jetty.servlet._
    import org.scalatra._

    val root = new ServletContextHandler(server, "/", ServletContextHandler.SESSIONS)
    root.setResourceBase(getClass().getResource("/public").toString())
    val defaultServletHolder = new ServletHolder(new DefaultServlet())
    defaultServletHolder.setName("default")
    defaultServletHolder.setInitParameter("dirAllowed", "false")
    root.addServlet(defaultServletHolder, "/*")
    root.addFilter(new FilterHolder(new WebFilter {
      private def updateAndPersist(f: MemoryImage => MemoryImage) {
        memoryImage.update { memoryImage =>
          val updated = f(memoryImage)
          PersistentDataSerialiser.write(PersistentData(filters = updated.filters, whitelist = updated.whitelist), dataFile)
          updated
        }
      }

      override protected def startTrustAnchorValidation(trustAnchors: Seq[TrustAnchor]) = Main.runValidator(trustAnchors)

      override def trustAnchors = memoryImage.get.trustAnchors

      override def roas = memoryImage.get.roas

      override def version = memoryImage.get.version

      override def lastUpdateTime = memoryImage.get.lastUpdateTime

      override protected def filters = memoryImage.get.filters
      override protected def addFilter(filter: IgnoreFilter) = updateAndPersist { _.addFilter(filter) }
      override protected def removeFilter(filter: IgnoreFilter) = updateAndPersist { _.removeFilter(filter) }

      override protected def whitelist = memoryImage.get.whitelist
      override protected def addWhitelistEntry(entry: RtrPrefix) = updateAndPersist { _.addWhitelistEntry(entry) }
      override protected def removeWhitelistEntry(entry: RtrPrefix) = updateAndPersist { _.removeWhitelistEntry(entry) }
    }), "/*", FilterMapping.ALL)
    server.setHandler(root)
    server
  }

  private def runWebServer(options: Options, dataFile: File): Unit = {
    val server = setup(new Server(options.httpPort), dataFile)

    sys.addShutdownHook({
      server.stop()
      logger.info("Bye, bye...")
    })
    server.start()
    logger.info("Welcome to the RIPE NCC RPKI Validator, now available on port " + options.httpPort + ". Hit CTRL+C to terminate.")
  }

  private def runRtrServer(options: Options): Unit = {
    var rtrServer = new RTRServer(port = options.rtrPort, noCloseOnError = options.noCloseOnError, noNotify = options.noNotify, getCurrentCacheSerial = {
      () => memoryImage.get.version
    }, getCurrentRtrPrefixes = {
      () => memoryImage.get.getDistinctRtrPrefixes()
    }, getCurrentNonce = {
      () => Main.nonce
    })
    rtrServer.startServer()
    registerMemoryImageListener((memoryImage => rtrServer.notify(memoryImage.version)))
  }
  
  private def registerMemoryImageListener(function: MemoryImage => Unit) = {
    memoryImageListener = memoryImageListener + (function)
  }

}
