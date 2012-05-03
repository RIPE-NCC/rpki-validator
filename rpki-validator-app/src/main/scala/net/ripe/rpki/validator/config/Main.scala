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
import rtr.Pdu
import rtr.RTRServer
import lib._
import models._
import bgp.preview._
import scalaz.{ Success, Failure }
import scala.concurrent.stm._
import akka.dispatch.Future
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.commons.certification.validation.ValidationOptions
import net.ripe.certification.validator.util.{ TrustAnchorExtractor }
import net.ripe.rpki.validator.statistics.FeedbackMetrics
import org.apache.http.impl.client.DefaultHttpClient
import org.joda.time.DateTimeUtils
import net.ripe.rpki.validator.statistics.Metric
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import net.ripe.certification.validator.util.TrustAnchorLocator

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

  val startedAt = System.currentTimeMillis

  val bgpRisDumps = Ref(Seq(
    BgpRisDump("http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"),
    BgpRisDump("http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz")))

  val bgpAnnouncementValidator = new BgpAnnouncementValidator

  val dataFile = new File(options.dataFileName).getCanonicalFile()
  val data = PersistentDataSerialiser.read(dataFile).getOrElse(PersistentData(whitelist = Whitelist()))

  val trustAnchors = loadTrustAnchors().all.map { ta => ta.copy(enabled = data.trustAnchorData.get(ta.name).map(_.enabled).getOrElse(true)) }
  val roas = ValidatedObjects(new TrustAnchors(trustAnchors.filter(ta => ta.enabled)))

  val userPreferences = Ref(data.userPreferences)

  val httpClient = new DefaultHttpClient(new ThreadSafeClientConnManager)
  val bgpRisDumpDownloader = new BgpRisDumpDownloader(httpClient)
  val feedbackMetrics = new FeedbackMetrics(httpClient, options.feedbackUri)
  feedbackMetrics.enabled = data.userPreferences.isFeedbackEnabled

  val memoryImage = Ref(
    MemoryImage(data.filters, data.whitelist, new TrustAnchors(trustAnchors), roas))

  def updateMemoryImage(f: MemoryImage => MemoryImage)(implicit transaction: MaybeTxn) {
    atomic { implicit transaction =>
      val oldVersion = memoryImage().version

      memoryImage.transform(f)

      if (oldVersion != memoryImage().version) {
        bgpAnnouncementValidator.startUpdate(main.bgpRisDumps().flatMap(_.announcedRoutes), memoryImage().getDistinctRtrPrefixes().toSeq)
        rtrServer.notify(memoryImage().version)
      }
    }
  }

  val rtrServer = runRtrServer()
  runWebServer()

  actorSystem.scheduler.schedule(initialDelay = 0 seconds, frequency = 10 seconds) { runValidator() }
  actorSystem.scheduler.schedule(initialDelay = 0 seconds, frequency = 2 hours) { refreshRisDumps() }
  actorSystem.scheduler.schedule(initialDelay = 0 seconds, frequency = 1 hour) { feedbackMetrics.sendMetrics() }

  private def loadTrustAnchors(): TrustAnchors = {
    import java.{ util => ju }
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/tal"), Array("tal"), false).asInstanceOf[ju.Collection[File]])
    TrustAnchors.load(tals.asScala, "tmp/tals")
  }

  private def refreshRisDumps() {
    Future.traverse(bgpRisDumps.single.get)(bgpRisDumpDownloader.download) foreach { dumps =>
      atomic { implicit transaction =>
        bgpRisDumps() = dumps
        bgpAnnouncementValidator.startUpdate(dumps.flatMap(_.announcedRoutes), memoryImage().getDistinctRtrPrefixes().toSeq)
      }
    }
  }

  private def runValidator() {
    import lib.DateAndTime._

    val now = new DateTime
    val needUpdating = for {
      ta <- memoryImage.single.get.trustAnchors.all if ta.status.isIdle
      Idle(nextUpdate, _) = ta.status
      if nextUpdate <= now
    } yield ta.name

    runValidator(needUpdating)
  }

  private def runValidator(trustAnchorNames: Seq[String]) {
    val maxStaleDays = userPreferences.single.get.maxStaleDays
    val trustAnchors = memoryImage.single.get.trustAnchors.all

    val taLocators = trustAnchorNames.flatMap { name => trustAnchors.find(_.name == name) }.map(_.locator)

    for (trustAnchorLocator <- taLocators) {
      Future {
        val process = new TrustAnchorValidationProcess(trustAnchorLocator, maxStaleDays) with TrackValidationProcess with MeasureValidationProcess with MeasureRsyncExecution with ValidationProcessLogger {
          override val memoryImage = main.memoryImage
        }
        try {
          process.runProcess match {
            case Success(validatedObjects) =>
              updateMemoryImage { _.updateValidatedObjects(trustAnchorLocator, validatedObjects.values.toSeq) }
            case Failure(_) =>
          }
        } finally {
          val now = DateTimeUtils.currentTimeMillis
          feedbackMetrics.store(process.metrics ++ process.rsyncMetrics ++ Metric.baseMetrics(now) ++ Metric.validatorMetrics(now, startedAt, ReleaseInfo.version))
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
        () => memoryImage.single.get.version
      },
      getCurrentRtrPrefixes = {
        () => memoryImage.single.get.getDistinctRtrPrefixes()
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
      private val dataFileLock = new Object()
      private def updateAndPersist(f: InTxn => Unit) {
        dataFileLock synchronized {
          val (image, userPreferences) = atomic { implicit transaction =>
            f(transaction)

            feedbackMetrics.enabled = main.userPreferences.get.isFeedbackEnabled

            (memoryImage.get, main.userPreferences.get)
          }
          PersistentDataSerialiser.write(
            PersistentData(filters = image.filters, whitelist = image.whitelist, userPreferences = userPreferences,
              trustAnchorData = image.trustAnchors.all.map(ta => ta.name -> TrustAnchorData(ta.enabled))(collection.breakOut)),
            dataFile)
        }
      }

      override protected def startTrustAnchorValidation(trustAnchors: Seq[String]) = main.runValidator(trustAnchors)

      override protected def trustAnchors = memoryImage.single.get.trustAnchors
      override protected def validatedObjects = memoryImage.single.get.validatedObjects
      override protected def version = memoryImage.single.get.version
      override protected def lastUpdateTime = memoryImage.single.get.lastUpdateTime

      override protected def filters = memoryImage.single.get.filters
      override protected def addFilter(filter: IgnoreFilter) = updateAndPersist { implicit transaction => updateMemoryImage(_.addFilter(filter)) }
      override protected def removeFilter(filter: IgnoreFilter) = updateAndPersist { implicit transaction => updateMemoryImage(_.removeFilter(filter)) }

      override protected def whitelist = memoryImage.single.get.whitelist
      override protected def addWhitelistEntry(entry: RtrPrefix) = updateAndPersist { implicit transaction => updateMemoryImage(_.addWhitelistEntry(entry)) }
      override protected def removeWhitelistEntry(entry: RtrPrefix) = updateAndPersist { implicit transaction => updateMemoryImage(_.removeWhitelistEntry(entry)) }

      override protected def bgpRisDumps = main.bgpRisDumps.single.get
      override protected def validatedAnnouncements = bgpAnnouncementValidator.validatedAnnouncements

      override protected def getRtrPrefixes = memoryImage.single.get.getDistinctRtrPrefixes()

      protected def sessionData = rtrServer.rtrSessions.allClientData

      // Software Update checker
      override def newVersionDetailFetcher = new OnlineNewVersionDetailFetcher(ReleaseInfo.version, () => scala.io.Source.fromURL(new java.net.URL("https://certification.ripe.net/content/static/validator/latest-version.properties"), "UTF-8").mkString)

      // UserPreferences
      override def userPreferences = main.userPreferences.single.get
      override def updateUserPreferences(userPreferences: UserPreferences) = updateAndPersist { implicit transaction => main.userPreferences.set(userPreferences) }

      override protected def updateTrustAnchorState(locator: TrustAnchorLocator, enabled: Boolean) = updateAndPersist { implicit transaction =>
        memoryImage.transform(_.updateTrustAnchorState(locator, enabled))
      }
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
