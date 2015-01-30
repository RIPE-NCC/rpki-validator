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
package net.ripe.rpki.validator.fetchers

import java.io.File
import java.net.URI
import java.nio.file.Files

import com.google.common.io.BaseEncoding
import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.validator.config.Http
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.HttpFetcherStore
import org.apache.http.client.methods.HttpGet
import org.apache.log4j.Logger

import scala.collection.JavaConversions._
import scala.math.BigInt
import scala.xml.Elem

case class FetcherConfig(rsyncDir: String = "")

trait Fetcher {
  type Callback = Either[BrokenObject, RepositoryObject[_]] => Unit
  def fetchRepo(uri: URI)(process: Callback)(processWithdraws: (URI, String) => Unit): Seq[String]
}

class RsyncFetcher(config: FetcherConfig) extends Fetcher {

  private val logger: Logger = Logger.getLogger(classOf[RsyncFetcher])

  private val OPTIONS = Seq("--update", "--times", "--copy-links", "--recursive", "--delete")

  private def walkTree[T](d: File)(f: File => Option[T]): Seq[T] = {
    if (d.isDirectory) {
      d.listFiles.map(walkTree(_)(f)).toSeq.flatten
    } else f(d) match {
      case Some(x) => Seq(x)
      case None => Seq()
    }
  }

  private[this] def withRsyncDir[T](uri: URI)(f: File => T) = {
    def uriToPath = uri.toString.replaceAll("rsync://", "")
    def destDir = {
      val rsyncPath = new File(config.rsyncDir + "/" + uriToPath)
      if (!rsyncPath.exists) {
        rsyncPath.mkdirs
      }
      rsyncPath
    }

    f(destDir)
  }

  def rsyncMethod(uri: URI, destDir: File) = {
    val r = new Rsync(uri.toString, destDir.getAbsolutePath)
    r.addOptions(OPTIONS)
    try {
      r.execute match {
        case 0 => Seq()
        case code => Seq( s"""Returned code: $code, stderr: ${r.getErrorLines.mkString("\n")}""")
      }
    } catch {
      case e: Exception => Seq( s"""Failed with exception, ${e.getMessage}""")
    }
  }

  override def fetchRepo(uri: URI)(process: Callback)(withdraw: (URI, String) => Unit = ((_, _) => ())): Seq[String] =
    fetchRepo(uri, rsyncMethod)(process)

  def fetchRepo(uri: URI, method: (URI, File) => Seq[String])(process: Callback): Seq[String] = withRsyncDir(uri) {
    destDir =>
      logger.info(s"Downloading the repository $uri to ${destDir.getAbsolutePath}")
      method(uri, destDir) ++ readObjects(destDir, uri, process)
  }

  def readObjects(tmpRoot: File, repoUri: URI, process: Callback): Seq[String] = {
    val replacement = {
      val s = repoUri.toString
      if (s.endsWith("/")) s.dropRight(1) else s
    }

    def rsyncUrl(f: File) =
      if (replacement.endsWith(f.getName))
        replacement
      else
        f.getAbsolutePath.replaceAll(tmpRoot.getAbsolutePath, replacement)

    walkTree(tmpRoot) {
      f =>
        val extension = f.getName.takeRight(3).toLowerCase
        var error: Option[String] = None
        val obj = extension match {
          case "cer" => process(CertificateObject.tryParse(rsyncUrl(f), readFile(f)))
          case "mft" => process(ManifestObject.tryParse(rsyncUrl(f), readFile(f)))
          case "crl" => process(CrlObject.tryParse(rsyncUrl(f), readFile(f)))
          case "roa" => process(RoaObject.tryParse(rsyncUrl(f), readFile(f)))
          case "gbr" => error = Some("We don't support GBR records yet")
          case _ => error = Some(s"Found unknown file $f")
        }
        error
    }
  }

  private def readFile(f: File) = Files.readAllBytes(f.toPath)
}

class HttpFetcher(config: FetcherConfig, store: HttpFetcherStore) extends Fetcher with Http {

  import scala.concurrent.ExecutionContext.Implicits.global
  import scala.concurrent._
  import scala.concurrent.duration._
  import scalaz.Scalaz._

  case class PublishUnit(uri: String, hash: String, base64: String)

  case class WithdrawUnit(uri: String, hash: String)

  case class NotificationDef(sessionId: String, serial: BigInt)

  case class SnapshotDef(url: String, hash: String)

  case class DeltaDef(serial: BigInt, url: URI, hash: String)

  case class Delta(deltaDef: DeltaDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  case class Snapshot(snapshotDef: SnapshotDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  case class Error(url: URI, message: String)

  private val base64 = BaseEncoding.base64()

  override def fetchRepo(notificationUri: URI)(process: Callback)(withdraw: (URI, String) => Unit = (_, _) => ()): Seq[String] =
    fetchRepoImpl(notificationUri)(process)(withdraw).map(p => s"url: ${p._1}, error: ${p._2}")

  def fetchRepoImpl(notificationUri: URI)(process: Callback)(processWithdraws: (URI, String) => Unit): Seq[(URI, String)] = {

    val notificationXml = getXml(notificationUri)

    val notificationDef = notificationXml >>= { xml =>
      try {
        Right(NotificationDef((xml \ "@session_id").text, BigInt((xml \ "@serial").text)))
      } catch {
        case e: NumberFormatException => Left(Error(notificationUri, "Couldn't parse serial number"))
        case e: Throwable => Left(Error(notificationUri, s"Error: ${e.getMessage}"))
      }
    }

    val snapshotDef = notificationXml >>= { xml =>
      (xml \ "snapshot").map(x => ((x \ "@uri").text, (x \ "@hash").text)) match {
        case Seq(s) => Right(SnapshotDef(s._1, s._2))
        case _ => Left(Error(notificationUri, "There should one and only one 'snapshot' element'"))
      }
    }

    type Units = (Seq[PublishUnit], Seq[WithdrawUnit])

    def returnSnapshot(lastLocalSerial: Option[BigInt]) = snapshotDef >>= { sd =>
      fetchSnapshot(new URI(sd.url), sd)
    } >>= { snapshot =>
      Right((snapshot.publishes, Seq(), lastLocalSerial))
    }

    val repositoryChanges = notificationDef >>= { notificationDef =>

      store.getSerial(notificationUri, notificationDef.sessionId) match {

        // the first time we go to this repository
        case None =>
          returnSnapshot(None)

        // TODO 0 is a weird number, figure out what to do
        case serial@Some(x) if x == BigInt(0) =>
          returnSnapshot(serial)

        // our local serial is already the latest one
        case serial@Some(lastLocalSerial) if lastLocalSerial == notificationDef.serial =>
          Right((Seq(), Seq(), serial))

        // something weird is happening, bail out
        case serial@Some(lastLocalSerial) if lastLocalSerial > notificationDef.serial =>
          Left(Error(notificationUri, s"Local serial $lastLocalSerial is larger then repository serial ${notificationDef.serial}"))

        case serial@Some(lastLocalSerial) =>
          notificationXml >>=
            parseDeltaDefs(notificationUri) >>=
            validateDeltaDefs(lastLocalSerial, notificationDef.serial) >>= { requiredDeltas =>

              if (requiredDeltas.head.serial > lastLocalSerial + 1) {
                returnSnapshot(serial)
              } else {
                val futures = requiredDeltas.map { dDef =>
                  future {
                    fetchDelta(dDef.url, dDef) >>= { d =>
                      Right((d.publishes, d.withdraw))
                    }
                  }
                }

                // wait for all the futures and bind their fetching results consecutively
                Await.result(Future.sequence(futures), 5.minutes).
                  foldLeft[Either[Error, Seq[Units]]] {
                  Right(Seq[Units]())
                } { (result, deltaUnits) =>
                  result >>= { r =>
                    deltaUnits >>= { dd => Right(r :+ dd)}
                  }
                } >>= { seqOfPairs =>
                  val pubs = seqOfPairs.map(_._1).flatten
                  val withs = seqOfPairs.map(_._2).flatten
                  Right((pubs, withs, serial))
                }
              }
          }
      }
    }

    repositoryChanges.right.foreach { x =>
      val (publishUnits, withdrawUnits, lastLocalSerial) = x
      publishUnits.foreach(parsePublishUnit(_, process))
      withdrawUnits.foreach(parseWithdrawUnit(_, processWithdraws))
      notificationDef.right.foreach { nd =>
        if (Some(nd.serial) != lastLocalSerial) {
          store.storeSerial(notificationUri, nd.sessionId, nd.serial)
        }
      }
    }

    repositoryChanges.left.toSeq.map(e => (e.url, e.message))
  }

  def parseDeltaDefs(notificationUri: URI)(xml: Elem) =
    try {
      Right((xml \ "delta").map(d => DeltaDef(BigInt((d \ "@serial").text), new URI((d \ "@uri").text), (d \ "@hash").text)))
    } catch {
      case e: Exception => Left(Error(notificationUri, s"Couldn't parse delta definitions: ${e.getMessage}"))
    }

  private def validateDeltaDefs(lastLocalSerial: BigInt, notificationSerial: BigInt)(deltaDefs: Seq[DeltaDef]) = {
    val requiredDeltas = deltaDefs.filter(_.serial > lastLocalSerial).sortBy(_.serial)
    val deltaWithMaxSerial = requiredDeltas.maxBy(_.serial)
    if (deltaWithMaxSerial.serial != notificationSerial) {
      Left(Error(deltaWithMaxSerial.url, "Latest delta serial is not the same as the one in notification file"))
    } else {
      // TODO check if they form a contiguous sequence
      Right(deltaDefs)
    }
  }

  private def parsePublishUnit(p: PublishUnit, process: Callback): Option[String] = {
    val extension = p.uri.takeRight(3).toLowerCase
    var error: Option[String] = None

    def decodeBase64 = try {
      base64.decode(p.base64.filterNot(Character.isWhitespace))
    } catch {
      case e: Throwable =>
        error = Some(e.getMessage)
        Array[Byte]()
    }

    val obj = extension match {
      case "cer" => process(CertificateObject.tryParse(p.uri, decodeBase64))
      case "mft" => process(ManifestObject.tryParse(p.uri, decodeBase64))
      case "crl" => process(CrlObject.tryParse(p.uri, decodeBase64))
      case "roa" => process(RoaObject.tryParse(p.uri, decodeBase64))
      case "gbr" => error = Some("We don't support GBR records yet")
      case _ => error = Some(s"Found unknown URI type ${p.uri}")
    }
    error
  }

  private def parseWithdrawUnit(p: WithdrawUnit, withdraw: (URI, String) => Unit): Option[String] = {
    try {
      withdraw(new URI(p.uri), p.hash)
      None
    } catch {
      case e: Exception => Some(s"Found unknown URI type ${p.uri}")
    }
  }

  def getXml(notificationUri: URI): Either[Error, Elem] = {
    try {
      val response = http.execute(new HttpGet(notificationUri))
      Right(scala.xml.XML.load(response.getEntity.getContent))
    } catch {
      case e: Exception => Left(Error(notificationUri, e.getMessage))
    }
  }

  private def fetchSnapshot(snapshotUrl: URI, snapshotDef: SnapshotDef): Either[Error, Snapshot] =
    getXml(snapshotUrl) >>= { xml =>
      getPublishUnits(snapshotUrl, xml) >>= { pu =>
        Right(Snapshot(snapshotDef, pu))
      }
    }


  private def fetchDelta(deltaUrl: URI, deltaDef: DeltaDef): Either[Error, Delta] =
    getXml(deltaUrl) >>= { xml =>
      getPublishUnits(deltaUrl, xml) >>= { pu =>
        getWithdrawUnits(deltaUrl, xml) >>= { wu =>
          Right(Delta(deltaDef, pu, wu))
        }
      }
    }

  private def getPublishUnits[T](url: URI, xml: Elem) : Either[Error, Seq[PublishUnit]] = {
      val publishes = (xml \ "publish").map(x => PublishUnit((x \ "@uri").text, (x \ "@hash").text, x.text))
      if (publishes.exists {
        p => Option(p.uri).exists(_.isEmpty) &&
          Option(p.hash).exists(_.isEmpty) &&
          Option(p.base64).exists(_.isEmpty)
      }) {
        // TODO Make it better
        Left(Error(url, "Mandatory attributes are absent"))
      }
      else
        Right(publishes)
    }

  private def getWithdrawUnits[T](url: URI, xml: Elem) : Either[Error, Seq[WithdrawUnit]] = {
    val withdraws = (xml \ "withdraw").map(x => WithdrawUnit((x \ "@uri").text, (x \ "@hash").text))
    if (withdraws.exists {
      p => Option(p.uri).exists(_.isEmpty) &&
        Option(p.hash).exists(_.isEmpty)
    }) {
      // TODO Make it better
      Left(Error(url, "Mandatory attributes are absent"))
    }
    else
      Right(withdraws)
  }

}

