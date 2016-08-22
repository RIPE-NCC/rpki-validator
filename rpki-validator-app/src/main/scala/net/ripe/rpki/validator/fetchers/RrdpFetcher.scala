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
/**
  * The BSD License
  *
  * Copyright (c) 2010-2012 RIPE NCC
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  * - Redistributions of source code must retain the above copyright notice,
  * this list of conditions and the following disclaimer.
  * - Redistributions in binary form must reproduce the above copyright notice,
  * this list of conditions and the following disclaimer in the documentation
  * and/or other materials provided with the distribution.
  * - Neither the name of the RIPE NCC nor the names of its contributors may be
  * used to endorse or promote products derived from this software without
  * specific prior written permission.
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

import java.net.URI
import java.util.concurrent.Executors

import com.google.common.io.BaseEncoding
import grizzled.slf4j.Logging
import net.ripe.rpki.validator.config.{ApplicationOptions, Http}
import net.ripe.rpki.validator.store.HttpFetcherStore
import org.apache.http.HttpStatus
import org.joda.time.DateTime

import scala.collection.immutable.Seq
import scala.math.BigInt
import scala.util.control.NonFatal
import scala.xml.Elem

object RrdpFetcher {

  private val lastFetchTimes = collection.mutable.Map[URI, DateTime]()
}

class RrdpFetcher(store: HttpFetcherStore) extends Fetcher with Http with Logging {

  import net.ripe.rpki.validator.fetchers.Fetcher._

  import scala.concurrent._
  import scala.concurrent.duration._
  import scalaz.Scalaz._

  class DeltaUnit

  case class PublishUnit(url: URI, hash: String, base64: String) extends DeltaUnit

  case class WithdrawUnit(url: URI, hash: String) extends DeltaUnit

  case class NotificationDef(sessionId: String, serial: BigInt)

  case class SnapshotDef(url: String, hash: String)

  case class DeltaDef(serial: BigInt, url: URI, hash: String)

  case class Delta(deltaDef: DeltaDef, units: Seq[DeltaUnit] = Seq())

  case class Snapshot(snapshotDef: SnapshotDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  private val base64 = BaseEncoding.base64()

  override def trustedCertsLocation = ApplicationOptions.trustedSslCertsLocation

  type ChangeSet = Seq[DeltaUnit]

  implicit val executionContext = ExecutionContext.fromExecutorService(Executors.newCachedThreadPool())

  override def fetch(notificationUrl: URI, fetcherListener: FetcherListener): Seq[Error] = {

    val fetchTime = new DateTime()
    val notificationXml: Either[Error, Option[Elem]] = getXmlIfModified(notificationUrl, RrdpFetcher.lastFetchTimes.get(notificationUrl))
    notificationXml match {
      case Left(error) => Seq(error)
      case Right(Some(xml)) =>
        RrdpFetcher.lastFetchTimes.put(notificationUrl, fetchTime)
        processNotificationXml(notificationUrl, xml, fetcherListener)
      case Right(None) => Seq[Error]()
    }
  }

  def processNotificationXml(notificationUrl: URI, xml: Elem, fetcherListener: FetcherListener): Seq[Error] = {

    val notificationDef = parseNotification(notificationUrl)(xml)
    val snapshotDef = parseSnapshotDef(notificationUrl)(xml)

    def returnSnapshot(lastLocalSerial: Option[BigInt]) = snapshotDef >>= { sd =>
      getSnapshot(new URI(sd.url), sd)
    } >>= { snapshot =>
      Right((snapshot.publishes, lastLocalSerial))
    }

    val repositoryChangeSet: Either[Error, (ChangeSet, Option[BigInt])] = notificationDef >>= { notificationDef =>

      store.getSerial(notificationUrl, notificationDef.sessionId) match {

        // the first time we go to this repository
        case None =>
          logger.info(s"No local serial number, downloading snapshot")
          returnSnapshot(None)

        // our local serial is already the latest one
        case serial@Some(lastLocalSerial) if lastLocalSerial == notificationDef.serial =>
          logger.info(s"lastLocalSerial = $lastLocalSerial and it's equal to the remote serial")
          Right((Seq[DeltaUnit](), serial))

        // something weird is happening, bail out
        case serial@Some(lastLocalSerial) if lastLocalSerial > notificationDef.serial =>
          logger.error(s"Local serial $lastLocalSerial is larger then repository serial ${notificationDef.serial}")
          Left(ParseError(notificationUrl, s"Local serial $lastLocalSerial is larger then repository serial ${notificationDef.serial}"))

        case serial@Some(lastLocalSerial) =>
          parseDeltaDefs(notificationUrl)(xml) >>=
            validateDeltaDefs(notificationUrl, lastLocalSerial, notificationDef.serial) >>= { requiredDeltas =>

            logger.info(s"lastLocalSerial = $lastLocalSerial and the remote serial is ${notificationDef.serial}")

            if (requiredDeltas.isEmpty) {
              if (lastLocalSerial < notificationDef.serial) {
                logger.info(s"requiredDeltas is empty, downloading snapshot")
                returnSnapshot(serial)
              }
              else
                Right((Seq(), serial))
            } else if (requiredDeltas.head.serial > lastLocalSerial + 1) {
              logger.info(s"requiredDeltas.head.serial is ${requiredDeltas.head.serial} and larger then ${lastLocalSerial + 1}, downloading snapshot")
              returnSnapshot(serial)
            } else {
              fetchDeltas(serial, requiredDeltas)
            }
          }
      }
    }

    repositoryChangeSet.fold(Seq(_), { changeSet =>
      val (deltaUnits, lastLocalSerial) = changeSet
      val deltaResults = deltaUnits.map(parseDeltaUnit(_, fetcherListener))
      val errors = deltaResults.collect { case Left(e) => e }
      if (errors.isEmpty) {
        notificationDef.right.foreach { nd =>
          logger.info(s"Serial from the notification file is ${nd.serial}, local is $lastLocalSerial")
          if (!(Some(nd.serial) == lastLocalSerial)) {
            logger.info(s"Storing local serial number for url=$notificationUrl, session_id=${nd.sessionId}, serial=${nd.serial}")
            store.storeSerial(notificationUrl, nd.sessionId, nd.serial)
          }
        }
      } else {
        logger.warn("Errors occurred during fetchng RRDP repository")
      }
      errors
    })
  }

  private def fetchDeltas(serial: Some[scala.BigInt], requiredDeltas: Seq[DeltaDef]): Either[Error, (ChangeSet,  Option[BigInt])] = {
    val futures: Seq[Future[Either[Error, ChangeSet]]] = requiredDeltas.map { dDef =>
      future {
        getDelta(dDef.url, dDef).map(d => d.units)
      }
    }

    // wait for all the futures and bind their fetching results consecutively
    Await.result(Future.sequence(futures), 5.minutes).
      foldLeft[Either[Error, ChangeSet]] {
      Right(Seq[DeltaUnit]())
    } { (sum: Either[Error, ChangeSet], result: Either[Error, ChangeSet]) =>
      sum >>= { (deltas: Seq[DeltaUnit]) =>
        result.map(deltas ++ _)
      }
    }.right.map((_, serial))
  }

  private def parseSnapshotDef(notificationUrl: URI)(xml: Elem): Either[Error, SnapshotDef] =
    (xml \ "snapshot").map(x => ((x \ "@uri").text, (x \ "@hash").text)) match {
      case Seq(s) => Right(SnapshotDef(s._1, s._2))
      case _ => Left(ParseError(notificationUrl, "There should one and only one 'snapshot' element'"))
    }

  private def parseNotification(notificationUrl: URI)(xml: Elem): Either[Error, NotificationDef] =
    try {
      Right(NotificationDef((xml \ "@session_id").text, BigInt((xml \ "@serial").text)))
    } catch {
      case e: NumberFormatException => Left(ParseError(notificationUrl, "Couldn't parse serial number"))
      case NonFatal(e) => Left(ParseError(notificationUrl, s"Error: ${e.getMessage}"))
    }

  private def parseDeltaDefs(notificationUrl: URI)(xml: Elem): Either[Error, Seq[DeltaDef]] =
    try {
      Right((xml \ "delta").map(d => DeltaDef(BigInt((d \ "@serial").text), new URI((d \ "@uri").text), (d \ "@hash").text)))
    } catch {
      case NonFatal(e) => Left(ParseError(notificationUrl, s"Couldn't parse delta definitions: ${e.getMessage}"))
    }

  private def validateDeltaDefs(uri: URI, lastLocalSerial: BigInt, notificationSerial: BigInt)(deltaDefs: Seq[DeltaDef]) = {
    val requiredDeltas = deltaDefs.filter(_.serial > lastLocalSerial).sortBy(_.serial)
    if (requiredDeltas.isEmpty)
      Right(requiredDeltas)
    else {
      val deltaWithMaxSerial = requiredDeltas.last
      if (deltaWithMaxSerial.serial != notificationSerial) {
        Left(ParseError(deltaWithMaxSerial.url, "Latest delta serial is not the same as the one in notification file"))
      } else {
        // TODO check if they form a contiguous sequence
        Right(requiredDeltas)
      }
    }
  }

  private def parseDeltaUnit(d: DeltaUnit, fetcherListener: FetcherListener) =
    d match {
      case p: PublishUnit => parsePublishUnit(p, fetcherListener)
      case w: WithdrawUnit => parseWithdrawUnit(w, fetcherListener)
    }

  private def parsePublishUnit(p: PublishUnit, fetcherListener: FetcherListener) =
    tryTo(p.url)(processingE) {
      base64.decode(p.base64.filterNot(Character.isWhitespace))
    } >>= { bytes =>
      processObject(p.url, bytes, fetcherListener)
    }

  private def parseWithdrawUnit(p: WithdrawUnit, fetcherListener: FetcherListener) =
    tryTo(p.url)(processingE) {
      fetcherListener.withdraw(p.url, p.hash)
    }

  def getXmlIfModified(xmlUrl: URI, ifModifiedSince: Option[DateTime]): Either[Error, Option[Elem]] =
    tryTo(xmlUrl)(connectionE) {
      logger.info(s"Fetching $xmlUrl")
      httpGetIfNotModified(xmlUrl.toString, ifModifiedSince)
    } >>= { response =>
      tryTo(xmlUrl)(parseE) {
        response.getStatusLine.getStatusCode match {
          case HttpStatus.SC_OK =>
            Some(scala.xml.XML.load(response.getEntity.getContent))
          case HttpStatus.SC_NOT_MODIFIED =>
            logger.info(s"Not fetching $xmlUrl because it was not modified since the last fetch at $ifModifiedSince")
            None
          case _ =>
            throw new RuntimeException(response.getStatusLine.getStatusCode + " " + response.getStatusLine.getReasonPhrase)
        }
      }
    }

  def getXml(xmlUrl: URI): Either[Error, Elem] =
    tryTo(xmlUrl)(connectionE) {
      logger.info(s"Fetching $xmlUrl")
      httpGet(xmlUrl.toString)
    } >>= { response =>
      tryTo(xmlUrl)(parseE) {
        response.getStatusLine.getStatusCode match {
          case HttpStatus.SC_OK =>
            scala.xml.XML.load(response.getEntity.getContent)
          case _ =>
            throw new RuntimeException(response.getStatusLine.getStatusCode + " " + response.getStatusLine.getReasonPhrase)
        }
      }
    }

  private def getSnapshot(snapshotUrl: URI, snapshotDef: SnapshotDef): Either[Error, Snapshot] =
    getXml(snapshotUrl) >>= { xml =>
      getUnits(snapshotUrl, xml) >>= { pu =>
        Right(Snapshot(snapshotDef, pu.asInstanceOf[Seq[PublishUnit]]))
      }
    }

  private def getDelta(deltaUrl: URI, deltaDef: DeltaDef): Either[Error, Delta] =
    getXml(deltaUrl) >>= { xml =>
      getUnits(deltaUrl, xml) >>= { pu =>
        Right(Delta(deltaDef, pu))
      }
    }

  private def getUnits[T](uri: URI, xml: Elem): Either[Error, Seq[DeltaUnit]] = {
    val publishes = (xml \ "_").map {
      case node@(<publish>{_}</publish>) => PublishUnit(new URI((node \ "@uri").text), (node \ "@hash").text, node.text)
      case node@(<withdraw/>) => WithdrawUnit(new URI((node \ "@uri").text), (node \ "@hash").text)
    }

    val invalidElement = publishes.find {
      case PublishUnit(url, hash, text) => url.toString.isEmpty && hash.isEmpty && text.isEmpty
      case WithdrawUnit(url, hash) => url.toString.isEmpty && hash.isEmpty
    }
    if (invalidElement.isDefined) {
      Left(ParseError(uri, s"Mandatory attributes are absent in element: $invalidElement"))
    }
    else
      Right(publishes)
  }
}

