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
package config

import java.io.File
import scala.collection.JavaConverters._
import org.apache.commons.io.FileUtils
import org.eclipse.jetty.server.Server
import org.joda.time.DateTime
import grizzled.slf4j.Logger
import net.ripe.certification.validator.util.TrustAnchorExtractor
import rtr.Pdu
import rtr.RTRServer
import lib._
import models._
import bgp.preview._
import scalaz.{ Success, Failure }
import akka.dispatch.Future

object Main {
  private val nonce: Pdu.Nonce = Pdu.randomNonce()

  def main(args: Array[String]): Unit = Options.parse(args) match {
    case Right(options) =>
      new Main(options)
    case Left(message) =>
      println(message)
      sys.exit(1)
  }
}
class Main(options: Options) { main =>
  import akka.util.duration._

  val logger = Logger[this.type]

  implicit val actorSystem = akka.actor.ActorSystem()

  val bgpAnnouncementValidator = new BgpAnnouncementValidator
  val trustAnchors = loadTrustAnchors()
  val roas = ValidatedObjects(trustAnchors)
  val dataFile = new File(options.dataFileName).getCanonicalFile()
  val data = PersistentDataSerialiser.read(dataFile).getOrElse(PersistentData(whitelist = Whitelist()))
  val memoryImage = new Atomic(
    MemoryImage(data.filters, data.whitelist, trustAnchors, roas, data.userPreferences.getOrElse(UserPreferences())))

  val rtrServer = runRtrServer()
  runWebServer()

  actorSystem.scheduler.schedule(initialDelay = 0 seconds, frequency = 10 seconds) { runValidator() }
  actorSystem.scheduler.schedule(initialDelay = 0 seconds, frequency = 2 hours) { refreshRisDumps() }

  private def loadTrustAnchors(): TrustAnchors = {
    import java.{ util => ju }
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/tal"), Array("tal"), false).asInstanceOf[ju.Collection[File]])
    TrustAnchors.load(tals.asScala, "tmp/tals")
  }

  @volatile
  private var bgpRisDumps = Seq(
    BgpRisDump(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz")),
    BgpRisDump(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz")))

  private def announcedRoutes(dumps: Seq[BgpRisDump]) = (for {
    dump <- bgpRisDumps
    entry <- dump.entries
    if entry.visibility >= BgpAnnouncementValidator.VISIBILITY_THRESHOLD
  } yield {
    BgpAnnouncement(entry.origin, entry.prefix)
  }).distinct

  private def refreshRisDumps() {
    Future.sequence(bgpRisDumps.map(BgpRisDump.refresh)) onSuccess {
      case dumps =>
        bgpAnnouncementValidator.startUpdate(announcedRoutes(dumps), memoryImage.get.getDistinctRtrPrefixes().toSeq)
        bgpRisDumps = dumps
    }
  }

  private def runValidator() {
    import lib.DateAndTime._

    val now = new DateTime
    val needUpdating = for {
      ta <- memoryImage.get.trustAnchors.all if ta.status.isIdle
      Idle(nextUpdate, _) = ta.status
      if nextUpdate <= now
    } yield ta

    runValidator(needUpdating)
  }

  private def runValidator(trustAnchors: Seq[TrustAnchor]) {
    for (ta <- trustAnchors; if ta.status.isIdle) {
      memoryImage.update { _.startProcessingTrustAnchor(ta.locator, "Updating certificate") }
      Future {
        try {
          val certificate = new TrustAnchorExtractor().extractTA(ta.locator, "tmp/tals")
          logger.info("Loaded trust anchor from location " + certificate.getLocation())
          memoryImage.update { _.startProcessingTrustAnchor(ta.locator, "Updating ROAs") }

          val validatedObjects = ValidatedObjects.fetchObjects(ta.locator, certificate)
          memoryImage.update { memoryImage =>
            val result = memoryImage.updateValidatedObjects(ta.locator, validatedObjects).finishedProcessingTrustAnchor(ta.locator, Success(certificate))
            bgpAnnouncementValidator.startUpdate(announcedRoutes(bgpRisDumps), result.getDistinctRtrPrefixes().toSeq)
            rtrServer.notify(result.version)
            result
          }
        } catch {
          case e: Exception =>
            logger.error("Error while validating trust anchor " + ta.locator.getCertificateLocation() + ": " + e, e)
            val message = if (e.getMessage != null) e.getMessage else e.toString
            memoryImage.update {
              _.finishedProcessingTrustAnchor(ta.locator, Failure(message))
            }
        }
      }
    }
  }

  private def runWebServer() {
    val server = setup(new Server(options.httpPort))

    sys.addShutdownHook({
      server.stop()
      logger.info("Terminating...")
    })
    server.start()
    logger.info("Welcome to the RIPE NCC RPKI Validator, now available on port " + options.httpPort + ". Hit CTRL+C to terminate.")
  }

  private def runRtrServer(): RTRServer = {
    val rtrServer = new RTRServer(port = options.rtrPort, noCloseOnError = options.noCloseOnError,
      noNotify = options.noNotify,
      getCurrentCacheSerial = {
        () => memoryImage.get.version
      },
      getCurrentRtrPrefixes = {
        () => memoryImage.get.getDistinctRtrPrefixes()
      },
      getCurrentNonce = {
        () => Main.nonce
      })
    rtrServer.startServer()
    rtrServer
  }

  private def setup(server: Server): Server = {
    import org.eclipse.jetty.servlet._
    import org.eclipse.jetty.server.handler.RequestLogHandler
    import org.eclipse.jetty.server.handler.HandlerCollection
    import org.eclipse.jetty.server.NCSARequestLog
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
          PersistentDataSerialiser.write(PersistentData(filters = updated.filters, whitelist = updated.whitelist, userPreferences = Some(updated.userPreferences)), dataFile)
          bgpAnnouncementValidator.startUpdate(announcedRoutes(bgpRisDumps), updated.getDistinctRtrPrefixes().toSeq)
          rtrServer.notify(updated.version)
          updated
        }
      }

      override protected def startTrustAnchorValidation(trustAnchors: Seq[TrustAnchor]) = main.runValidator()

      override protected def trustAnchors = memoryImage.get.trustAnchors
      override protected def validatedObjects = memoryImage.get.validatedObjects
      override protected def version = memoryImage.get.version
      override protected def lastUpdateTime = memoryImage.get.lastUpdateTime

      override protected def filters = memoryImage.get.filters
      override protected def addFilter(filter: IgnoreFilter) = updateAndPersist { _.addFilter(filter) }
      override protected def removeFilter(filter: IgnoreFilter) = updateAndPersist { _.removeFilter(filter) }

      override protected def whitelist = memoryImage.get.whitelist
      override protected def addWhitelistEntry(entry: RtrPrefix) = updateAndPersist { _.addWhitelistEntry(entry) }
      override protected def removeWhitelistEntry(entry: RtrPrefix) = updateAndPersist { _.removeWhitelistEntry(entry) }

      override protected def bgpRisDumps = main.bgpRisDumps
      override protected def validatedAnnouncements = bgpAnnouncementValidator.validatedAnnouncements

      override protected def getRtrPrefixes = memoryImage.get.getDistinctRtrPrefixes()

      protected def sessionData = rtrServer.rtrSessions.allClientData

      // Software Update checker
      override def getNewVersionDetailFetcher = new OnlineNewVersionDetailFetcher(ReleaseInfo.version, () => scala.io.Source.fromURL(new java.net.URL("https://certification.ripe.net/content/static/validator/latest-version.properties"), "UTF-8").mkString)
      override def getUserPreferences = memoryImage.get.userPreferences
      override def updateUserPreferences(userPreferences: UserPreferences) = updateAndPersist { _.updateUserPreferences(userPreferences) }
    }), "/*", FilterMapping.ALL)

    val requestLogHandler = {
      val handler = new RequestLogHandler()
      val requestLog = new NCSARequestLog("./log/access.log")
      requestLog.setRetainDays(90)
      requestLog.setAppend(true)
      requestLog.setExtended(false)
      requestLog.setLogLatency(true)
      handler.setRequestLog(requestLog)
      handler
    }

    val handlers = new HandlerCollection()
    handlers.addHandler(root)
    handlers.addHandler(requestLogHandler)
    server.setHandler(handlers)
    server
  }

}
