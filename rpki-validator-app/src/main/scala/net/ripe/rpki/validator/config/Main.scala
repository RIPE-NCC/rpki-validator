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

import org.eclipse.jetty.server.Server
import org.apache.commons.io.FileUtils
import scala.collection.JavaConverters._
import net.ripe.certification.validator.util.TrustAnchorExtractor
import net.ripe.rpki.validator.rtr.RTRServer
import models._
import java.util.concurrent.atomic.AtomicReference
import scalaz.concurrent.Promise
import net.ripe.rpki.validator.rtr.Pdu
import org.joda.time.DateTime
import net.liftweb.json.{Formats, Serializer, DefaultFormats, Serialization}
import net.liftweb.json.JsonAST.{JInt, JString}
import net.ripe.ipresource.{IpRange, Asn}
import java.io.{IOException, File}
import grizzled.slf4j.{Logging, Logger}

case class MemoryImage(whitelist: Whitelist, trustAnchors: TrustAnchors, roas: Roas, version: Int = 0) {

  def addWhitelistEntry(entry: WhitelistEntry) = copy(whitelist = whitelist.addEntry(entry))

  def removeWhitelistEntry(entry: WhitelistEntry) = copy(whitelist = whitelist.removeEntry(entry))
}

case class PersistentData(schemaVersion: Int = 0, whitelist: Whitelist = Whitelist())

class PersistentDataSerialiser {

  object AsnSerialiser extends Serializer[Asn] {
    def deserialize(implicit format: Formats) = {
      case (_, JInt(i)) => new Asn(i.longValue())
    }

    def serialize(implicit format: Formats) = {
      case asn: Asn => new JInt(new BigInt(asn.getValue()))
    }
  }

  object IpRangeSerialiser extends Serializer[IpRange] {
    def deserialize(implicit format: Formats) = {
      case (_, JString(s)) => IpRange.parse(s)
    }

    def serialize(implicit format: Formats) = {
      case range: IpRange => new JString(range.toString)
    }
  }

  implicit val formats: Formats = DefaultFormats + AsnSerialiser + IpRangeSerialiser

  def serialise(data: PersistentData) = Serialization.write(data)

  def deserialise(json: String): PersistentData = Serialization.read[PersistentData](json)
}

object PersistentDataSerialiser extends PersistentDataSerialiser with Logging {
  def write(data: PersistentData, file: File) {
    file.getParentFile.mkdirs()
    val tempFile: File = File.createTempFile("rkpi", "dat", file.getParentFile)
    FileUtils.writeStringToFile(tempFile, serialise(data), "UTF-8")
    if (!tempFile.renameTo(file)) throw new IOException("Error writing file: " + file.getAbsolutePath)
  }

  def read(file: File): Option[PersistentData] = try {
    val json: String = FileUtils.readFileToString(file, "UTF-8")
    Some(deserialise(json))
  } catch {
    case e: IOException =>
      warn("Error reading "+ file.getAbsolutePath + ": " + e.getMessage)
      None
  }
}

class Atomic[T](value: T) {
  private val db: AtomicReference[T] = new AtomicReference(value)

  def get = db.get

  var lastUpdateTime: DateTime = new DateTime

  final def update(f: T => T) {
    var current = get
    var updated = f(current)
    while (!db.compareAndSet(current, updated)) {
      current = get
      updated = f(current)
    }
    lastUpdateTime = new DateTime
  }

}

trait UpdateListener {
  def notify(serial: Long)
}

object Main {

  val logger = Logger[this.type]

  private val nonce: Pdu.Nonce = Pdu.randomNonce()

  private var database: Atomic[MemoryImage] = null
  private var listeners = List[UpdateListener]()

  def main(args: Array[String]): Unit = Options.parse(args) match {
    case Right(options) => run(options)
    case Left(message) => error(message)
  }

  private def run(options: Options): Unit = {
    val trustAnchors = loadTrustAnchors()
    val roas = Roas(trustAnchors)
    val dataFile = new File(options.dataFileName).getCanonicalFile()
    val data = PersistentDataSerialiser.read(dataFile).getOrElse(PersistentData(whitelist = Whitelist()))
    database = new Atomic(MemoryImage(data.whitelist, trustAnchors, roas))

    runWebServer(options, dataFile)
    runRtrServer(options)
  }

  private def error(message: String) = {
    println(message)
    sys.exit(1)
  }

  def registerListener(newListener: UpdateListener) = {
    listeners = listeners ++ List(newListener)
  }

  def loadTrustAnchors(): TrustAnchors = {
    import java.{util => ju}
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/tal"), Array("tal"), false).asInstanceOf[ju.Collection[File]])
    val trustAnchors = TrustAnchors.load(tals.asScala, "tmp/tals")
    for (ta <- trustAnchors.all) {
      Promise {
        val certificate = new TrustAnchorExtractor().extractTA(ta.locator, "tmp/tals")
        logger.info("Loaded trust anchor from location " + certificate.getLocation())
        database.update {
          db =>
            db.copy(trustAnchors = db.trustAnchors.update(ta.locator, certificate))
        }
        val validatedRoas = Roas.fetchObjects(ta.locator, certificate)
        database.update {
          db =>
            db.copy(roas = db.roas.update(ta.locator, validatedRoas), version = db.version + 1)
        }
        listeners.foreach {
          listener => listener.notify(database.get.version)
        }
      }
    }
    trustAnchors
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
      override def trustAnchors = database.get.trustAnchors

      override def roas = database.get.roas

      override def version = database.get.version

      override def lastUpdateTime = database.lastUpdateTime

      override def whitelist = database.get.whitelist

      override def addWhitelistEntry(entry: WhitelistEntry) = database synchronized {
        database.update(_.addWhitelistEntry(entry))
        PersistentDataSerialiser.write(PersistentData(whitelist = database.get.whitelist), dataFile)
      }

      override def removeWhitelistEntry(entry: WhitelistEntry) = database synchronized {
        database.update(_.removeWhitelistEntry(entry))
        PersistentDataSerialiser.write(PersistentData(whitelist = database.get.whitelist), dataFile)
      }
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
      () => database.get.version
    }, getCurrentRoas = {
      () => database.get.roas
    }, getCurrentNonce = {
      () => Main.nonce
    })
    rtrServer.startServer()
    registerListener(rtrServer)
  }

}
