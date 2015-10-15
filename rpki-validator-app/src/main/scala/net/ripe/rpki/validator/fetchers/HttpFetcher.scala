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

import java.net.URI

import com.google.common.io.BaseEncoding
import grizzled.slf4j.Logging
import net.ripe.rpki.validator.config.{ApplicationOptions, Http}
import net.ripe.rpki.validator.store.HttpFetcherStore
import org.apache.http.HttpStatus
import org.apache.http.client.methods.HttpGet

import scala.math.BigInt
import scala.xml.Elem

class HttpFetcher(store: HttpFetcherStore) extends Fetcher with Http  with Logging {

  import net.ripe.rpki.validator.fetchers.Fetcher._

  import scala.concurrent.ExecutionContext.Implicits.global
  import scala.concurrent._
  import scala.concurrent.duration._
  import scalaz.Scalaz._

  case class PublishUnit(url: URI, hash: String, base64: String)

  case class WithdrawUnit(url: URI, hash: String)

  case class NotificationDef(sessionId: String, serial: BigInt)

  case class SnapshotDef(url: String, hash: String)

  case class DeltaDef(serial: BigInt, url: URI, hash: String)

  case class Delta(deltaDef: DeltaDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  case class Snapshot(snapshotDef: SnapshotDef, publishes: Seq[PublishUnit], withdraw: Seq[WithdrawUnit] = Seq())

  private val base64 = BaseEncoding.base64()

  override def trustedCertsLocation = ApplicationOptions.trustedSslCertsLocation

  override def fetch(notificationUrl: URI, fetcherListener: FetcherListener): Seq[Error] = {

    val notificationXml = getXml(notificationUrl)
    val notificationDef = notificationXml >>= fetchNotification(notificationUrl)
    val snapshotDef = notificationXml >>= parseSnapshotDef(notificationUrl)

    type ChangeSet = (Seq[PublishUnit], Seq[WithdrawUnit])

    def returnSnapshot(lastLocalSerial: Option[BigInt]) = snapshotDef >>= { sd =>
      getSnapshot(new URI(sd.url), sd)
    } >>= { snapshot =>
      Right((snapshot.publishes, Seq(), lastLocalSerial))
    }

    val repositoryChangeSet = notificationDef >>= { notificationDef =>

      store.getSerial(notificationUrl, notificationDef.sessionId) match {

        // the first time we go to this repository
        case None =>
          returnSnapshot(None)

        case serial@Some(x) if x == BigInt(0) =>
          Left(Error(notificationUrl, s"Serial must be a positive number"))

        // our local serial is already the latest one
        case serial@Some(lastLocalSerial) if lastLocalSerial == notificationDef.serial =>
          Right((Seq(), Seq(), serial))

        // something weird is happening, bail out
        case serial@Some(lastLocalSerial) if lastLocalSerial > notificationDef.serial =>
          Left(Error(notificationUrl, s"Local serial $lastLocalSerial is larger then repository serial ${notificationDef.serial}"))

        case serial@Some(lastLocalSerial) =>
          notificationXml >>=
            parseDeltaDefs(notificationUrl) >>=
            validateDeltaDefs(notificationUrl, lastLocalSerial, notificationDef.serial) >>= { requiredDeltas =>

            if (requiredDeltas.isEmpty) {
              if (lastLocalSerial < notificationDef.serial)
                returnSnapshot(serial)
              else
                Right((Seq(), Seq(), serial))
            } else if (requiredDeltas.head.serial > lastLocalSerial + 1) {
              returnSnapshot(serial)
            } else {
              val futures = requiredDeltas.map { dDef =>
                future {
                  getDelta(dDef.url, dDef) >>= { d =>
                    Right((d.publishes, d.withdraw))
                  }
                }
              }

              // wait for all the futures and bind their fetching results consecutively
              Await.result(Future.sequence(futures), 5.minutes).
                foldLeft[Either[Error, Seq[ChangeSet]]] {
                Right(Seq[ChangeSet]())
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

    repositoryChangeSet.fold(Seq(_), { changeSet =>
      val (publishUnits, withdrawUnits, lastLocalSerial) = changeSet
      val publishResults = publishUnits.map(parsePublishUnit(_, fetcherListener))
      val withdrawResults = withdrawUnits.map(parseWithdrawUnit(_, fetcherListener))
      val errors = publishResults.collect { case Left(e) => e} ++ withdrawResults.collect { case Left(e) => e}
      if (errors.isEmpty) {
        notificationDef.right.foreach { nd =>
          if (Some(nd.serial) != lastLocalSerial) {
            store.storeSerial(notificationUrl, nd.sessionId, nd.serial)
          }
        }
      }
      errors
    })
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

  private def validateDeltaDefs(uri: URI, lastLocalSerial: BigInt, notificationSerial: BigInt)(deltaDefs: Seq[DeltaDef]) = {
    val requiredDeltas = deltaDefs.filter(_.serial > lastLocalSerial).sortBy(_.serial)
    if (requiredDeltas.isEmpty)
      Right(deltaDefs)
    else {
      val deltaWithMaxSerial = requiredDeltas.last
      if (deltaWithMaxSerial.serial != notificationSerial) {
        Left(Error(deltaWithMaxSerial.url, "Latest delta serial is not the same as the one in notification file"))
      } else {
        // TODO check if they form a contiguous sequence
        Right(deltaDefs)
      }
    }
  }

  private def parsePublishUnit(p: PublishUnit, fetcherListener: FetcherListener) =
    tryTo(p.url) {
      base64.decode(p.base64.filterNot(Character.isWhitespace))
    } >>= { bytes =>
      processObject(p.url, bytes, fetcherListener)
    }

  private def parseWithdrawUnit(p: WithdrawUnit, fetcherListener: FetcherListener) =
    tryTo(p.url) {
      fetcherListener.withdraw(p.url, p.hash)
    }

  def getXml(notificationUrl: URI) =
    tryTo(notificationUrl) {
      val response = http.execute(new HttpGet(notificationUrl.toString))
      response.getStatusLine.getStatusCode match {
        case HttpStatus.SC_OK =>
          scala.xml.XML.load(response.getEntity.getContent)
        case _ =>
          throw new RuntimeException(response.getStatusLine.getStatusCode + " " + response.getStatusLine.getReasonPhrase)
      }
    }

  private def getSnapshot(snapshotUrl: URI, snapshotDef: SnapshotDef): Either[Error, Snapshot] =
    getXml(snapshotUrl) >>= { xml =>
      getPublishUnits(snapshotUrl, xml) >>= { pu =>
        Right(Snapshot(snapshotDef, pu))
      }
    }


  private def getDelta(deltaUrl: URI, deltaDef: DeltaDef): Either[Error, Delta] =
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

