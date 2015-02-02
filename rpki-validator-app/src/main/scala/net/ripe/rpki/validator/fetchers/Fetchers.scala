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

trait FetcherListener {
  def processObject(repoObj: RepositoryObject[_])
  def processBroken(brokenObj: BrokenObject)
  def withdraw(url: URI, hash: String)
}

object Fetcher {
  case class Error(url: URI, message: String)
}

trait Fetcher {

  import Fetcher._

  type MaybeRepoObject = Either[BrokenObject, RepositoryObject[_]]
  type Callback = MaybeRepoObject => MaybeRepoObject
  def fetchRepo(url: URI, process: FetcherListener): Seq[Error]

  def processObject(rsyncUrl: URI, f: Array[Byte], fetcherListener: FetcherListener) = {
    val extension = rsyncUrl.toString.takeRight(3).toLowerCase
    val repoObject = extension match {
      case "cer" =>
        CertificateObject.tryParse(rsyncUrl.toString, f).left.map {
          bo =>
            fetcherListener.processBroken(bo)
            Error(rsyncUrl, "Could parse object")
        }
      case "mft" => ManifestObject.tryParse(rsyncUrl.toString, f).left.map {
        bo =>
          fetcherListener.processBroken(bo)
          Error(rsyncUrl, "Could parse object")
      }
      case "crl" => CrlObject.tryParse(rsyncUrl.toString, f).left.map {
        bo =>
          fetcherListener.processBroken(bo)
          Error(rsyncUrl, "Could parse object")
      }
      case "roa" => RoaObject.tryParse(rsyncUrl.toString, f).left.map {
        bo =>
          fetcherListener.processBroken(bo)
          Error(rsyncUrl, "Could parse object")
      }
      case "gbr" =>
        Left(Error(rsyncUrl, "We don't support GBR records yet"))
      case _ =>
        Left(Error(rsyncUrl, "Found unknown file $f"))
    }
    repoObject.right.foreach {
      ro => fetcherListener.processObject(ro)
    }
    repoObject
  }

}

class RsyncFetcher(config: FetcherConfig) extends Fetcher {

  import Fetcher._

  private val logger: Logger = Logger.getLogger(classOf[RsyncFetcher])

  private val OPTIONS = Seq("--update", "--times", "--copy-links", "--recursive", "--delete")

  private def walkTree[T1, T2](d: File)(f: File => Either[T1, T2]): Seq[T1] = {
    if (d.isDirectory) {
      d.listFiles.map(walkTree(_)(f)).toSeq.flatten
    } else f(d).fold(Seq(_), { _ => Seq() })
  }

  private[this] def withRsyncDir[T](url: URI)(f: File => T) = {
    def urlToPath = url.toString.replaceAll("rsync://", "")
    def destDir = {
      val rsyncPath = new File(config.rsyncDir + "/" + urlToPath)
      if (!rsyncPath.exists) {
        rsyncPath.mkdirs
      }
      rsyncPath
    }

    f(destDir)
  }

  def rsyncMethod(url: URI, destDir: File): Option[Error] = {
    val r = new Rsync(url.toString, destDir.getAbsolutePath)
    r.addOptions(OPTIONS)
    try {
      r.execute match {
        case 0 => None
        case code => Some(Error(url, s"""Returned code: $code, stderr: ${r.getErrorLines.mkString("\n")}"""))
      }
    } catch {
      case e: Exception => Some(Error(url, s"""Failed with exception, ${e.getMessage}"""))
    }
  }

  override def fetchRepo(url: URI, fetcherListener: FetcherListener): Seq[Error] =
    fetchRepo(url, rsyncMethod, fetcherListener)

  def fetchRepo(url: URI, method: (URI, File) => Option[Error], fetcherListener: FetcherListener): Seq[Error] = withRsyncDir(url) {
    destDir =>
      logger.info(s"Downloading the repository $url to ${destDir.getAbsolutePath}")
      method(url, destDir).toSeq ++ readObjects(destDir, url, fetcherListener)
  }

  def readObjects(tmpRoot: File, repoUrl: URI, fetcherListener: FetcherListener): Seq[Error] = {
    val replacement = {
      val s = repoUrl.toString
      if (s.endsWith("/")) s.dropRight(1) else s
    }

    def rsyncUrl(f: File) =
      new URI(if (replacement.endsWith(f.getName))
        replacement
      else
        f.getAbsolutePath.replaceAll(tmpRoot.getAbsolutePath, replacement))

    walkTree(tmpRoot) {
      f =>
        processObject(rsyncUrl(f), readFile(f), fetcherListener)
    }
  }

  private def readFile(f: File) = Files.readAllBytes(f.toPath)
}

class HttpFetcher(config: FetcherConfig, store: HttpFetcherStore) extends Fetcher with Http {

  import scala.concurrent.ExecutionContext.Implicits.global
  import scala.concurrent._
  import scala.concurrent.duration._
  import scalaz.Scalaz._
  import Fetcher._

  case class PublishUnit(url: URI, hash: String, base64: String)

  case class WithdrawUnit(url: URI, hash: String)

  case class NotificationDef(sessionId: String, serial: BigInt)

  case class SnapshotDef(url: String, hash: String)

  case class DeltaDef(serial: BigInt, url: URI, hash: String)

  case class Delta(deltaDef: DeltaDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  case class Snapshot(snapshotDef: SnapshotDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  private val base64 = BaseEncoding.base64()

  override def fetchRepo(notificationUrl: URI, fetcherListener: FetcherListener): Seq[Error] = {

    val notificationXml = getXml(notificationUrl)
    val notificationDef = notificationXml >>= fetchNotification(notificationUrl)
    val snapshotDef = notificationXml >>= parseSnapshotDef(notificationUrl)

    type Units = (Seq[PublishUnit], Seq[WithdrawUnit])

    def returnSnapshot(lastLocalSerial: Option[BigInt]) = snapshotDef >>= { sd =>
      fetchSnapshot(new URI(sd.url), sd)
    } >>= { snapshot =>
      Right((snapshot.publishes, Seq(), lastLocalSerial))
    }

    val repositoryChanges = notificationDef >>= { notificationDef =>

      store.getSerial(notificationUrl, notificationDef.sessionId) match {

        // the first time we go to this repository
        case None =>
          returnSnapshot(None)

        case serial@Some(x) if x == BigInt(0) =>
          Left(Error(notificationUrl, s"Serial must be a positLocal number"))

        // our local serial is already the latest one
        case serial@Some(lastLocalSerial) if lastLocalSerial == notificationDef.serial =>
          Right((Seq(), Seq(), serial))

        // something weird is happening, bail out
        case serial@Some(lastLocalSerial) if lastLocalSerial > notificationDef.serial =>
          Left(Error(notificationUrl, s"Local serial $lastLocalSerial is larger then repository serial ${notificationDef.serial}"))

        case serial@Some(lastLocalSerial) =>
          notificationXml >>=
            parseDeltaDefs(notificationUrl) >>=
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
      val p = publishUnits.map(parsePublishUnit(_, fetcherListener))
      val w = withdrawUnits.map(parseWithdrawUnit(_, fetcherListener))
      notificationDef.right.foreach { nd =>
        if (Some(nd.serial) != lastLocalSerial) {
          store.storeSerial(notificationUrl, nd.sessionId, nd.serial)
        }
      }
    }

    repositoryChanges.left.toSeq
  }

  private def parseSnapshotDef(notificationUrl: URI)(xml: Elem) =
    (xml \ "snapshot").map(x => ((x \ "@uri").text, (x \ "@hash").text)) match {
      case Seq(s) => Right(SnapshotDef(s._1, s._2))
      case _ => Left(Error(notificationUrl, "There should one and only one 'snapshot' element'"))
    }

  private def fetchNotification(notificationUrl: URI)(xml: Elem) =
    try {
      Right(NotificationDef((xml \ "@session_id").text, BigInt((xml \ "@serial").text)))
    } catch {
      case e: NumberFormatException => Left(Error(notificationUrl, "Couldn't parse serial number"))
      case e: Throwable => Left(Error(notificationUrl, s"Error: ${e.getMessage}"))
    }

  private def parseDeltaDefs(notificationUrl: URI)(xml: Elem) =
    try {
      Right((xml \ "delta").map(d => DeltaDef(BigInt((d \ "@serial").text), new URI((d \ "@uri").text), (d \ "@hash").text)))
    } catch {
      case e: Exception => Left(Error(notificationUrl, s"Couldn't parse delta definitions: ${e.getMessage}"))
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

  private def parsePublishUnit(p: PublishUnit, fetcherListener: FetcherListener) = {
    def decodeBase64 = try {
      Right(base64.decode(p.base64.filterNot(Character.isWhitespace)))
    } catch {
      case e: Exception => Left(Error(p.url, e.getMessage))
    }
    decodeBase64 >>= { bytes =>
      Right(processObject(p.url, bytes, fetcherListener))
    }
  }

  private def parseWithdrawUnit(p: WithdrawUnit, fetcherListener: FetcherListener) = {
    try {
      Right(fetcherListener.withdraw(p.url, p.hash))
    } catch {
      case e: Exception => Left(Error(p.url, e.getMessage))
    }
  }

  def getXml(notificationUrl: URI): Either[Error, Elem] = {
    try {
      val response = http.execute(new HttpGet(notificationUrl.toString))
      Right(scala.xml.XML.load(response.getEntity.getContent))
    } catch {
      case e: Exception => Left(Error(notificationUrl, e.getMessage))
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
    val publishes = (xml \ "publish").map(x => PublishUnit(new URI((x \ "@uri").text), (x \ "@hash").text, x.text))
    if (publishes.exists {
      p => Option(p.url).exists(_.toString.isEmpty) &&
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
    val withdraws = (xml \ "withdraw").map(x => WithdrawUnit(new URI((x \ "@uri").text), (x \ "@hash").text))
    if (withdraws.exists {
      p => Option(p.url).exists(_.toString.isEmpty) &&
        Option(p.hash).exists(_.isEmpty)
    }) {
      // TODO Make it better
      Left(Error(url, "Mandatory attributes are absent"))
    }
    else
      Right(withdraws)
  }

}

