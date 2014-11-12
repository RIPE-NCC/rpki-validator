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
package net.ripe.rpki.validator.rrdp

import scala.Array.canBuildFrom
import scala.xml.Node
import scala.xml.XML

import java.math.BigInteger
import java.net.URI
import java.nio.charset.Charset
import java.util.UUID

import org.joda.time.DateTime

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.ValidationResult

import org.apache.commons.lang.StringUtils
import sun.misc.BASE64Decoder

sealed trait RrdpFetcherUpdateResult
case class RrdpFetcherWithoutUpdates(fetcher: RrdpFetcher) extends RrdpFetcherUpdateResult
case class RrdpFetcherWithUpdates(fetcher: RrdpFetcher, updates: List[PublicationProtocolMessage]) extends RrdpFetcherUpdateResult
case object RrdpFetcherSessionLost extends RrdpFetcherUpdateResult

case class RrdpFetcher(notifyUri: URI, sessionId: UUID, serial: BigInteger, lastUpdated: DateTime = DateTime.now) {

  /**
   * Will return one of the following results:
   *   RrdpFetcherSessionLost      in case the sessionId has been modified, you should re-initialise a fetcher, and maybe purge your cache
   *   RrdpFetcherWithoutUpdates   in case there are no updates
   *   RrdpFetcherWithUpdates      in case there are updates, will use deltas if available, or latest snapshot and available deltas from that point
   */
  def update(): RrdpFetcherUpdateResult = {
    val newNotification = Notification.fromXml(XML.load(notifyUri))

    if (!newNotification.sessionId.equals(sessionId)) {
      RrdpFetcherSessionLost
    } else if (newNotification.serial.equals(serial)) {
      RrdpFetcherWithoutUpdates(this)
    } else {
      newNotification.updatePath(serial) match {
        case withDeltas: UpdatePathWithDeltas => {
          val updates = withDeltas.deltaRefs.map(_.retrieve).flatMap(_.deltas).flatMap(_.messages)
          val last = withDeltas.deltaRefs.last.serial
          RrdpFetcherWithUpdates(copy(serial = last), updates = updates)
        }
        case withSnapshot: UpdatePathWithSnapshot => {
          val snapshot = withSnapshot.snaphotRef.retrieve
          RrdpFetcherWithUpdates(copy(serial = snapshot.serial), updates = snapshot.publishes)
        }
      }
    }
  }
}

object RrdpFetcher {
  def initialise(notifyUri: URI) = {
    val notifcation = Notification.fromXml(XML.load(notifyUri))
    RrdpFetcher(notifyUri, notifcation.sessionId, BigInteger.valueOf(-1L))
  }
}

case class ReferenceHash(hash: String) {
  def matches(other: Array[Byte]): Boolean = StringUtils.equals(hash, ReferenceHash.fromBytes(other).hash)
  override def toString = hash
}

object ReferenceHash {
  def fromBytes(bytes: Array[Byte]) = {
    fromManifestHash(ManifestCms.hashContents(bytes))
  }

  def fromManifestHash(bytes: Array[Byte]) = {
    ReferenceHash(bytes.map("%02X" format _).mkString)
  }

  def fromXml(xml: Node) = {
    val bytes = xml.toString.getBytes(Charset.forName("UTF8"))
    fromBytes(bytes)
  }
}

sealed trait DeltaProtocolMessage

case class Notification(sessionId: UUID, serial: BigInteger, snapshot: SnapshotReference, deltas: List[DeltaReference] = List.empty) extends DeltaProtocolMessage {

  /**
   * Returns a list of deltas that can be used to get up to the latest.
   *
   * If no continuous chain of deltas can be found, the snapshot is returned instead.
   */
  def updatePath(oldSerial: BigInteger): UpdatePath = {
    
    val nextSerial = oldSerial.add(BigInteger.ONE)

    if (oldSerial.equals(BigInteger.valueOf(-1l))) {
      UpdatePathWithSnapshot(snapshot)
    } else {
      deltas.find(_.serial == nextSerial) match {
        case Some(delta) => {
          if (delta.serial == serial) {
            UpdatePathWithDeltas(deltaRefs = List(delta))
          } else {
            updatePath(nextSerial) match {
              case withDeltas: UpdatePathWithDeltas => UpdatePathWithDeltas(deltaRefs = List(delta) ++ withDeltas.deltaRefs)
              case withSnapshot: UpdatePathWithSnapshot => withSnapshot
            }
          }
        }
        case None => UpdatePathWithSnapshot(snapshot)
      }
    }

  }
}

object Notification {
  def fromXml(xml: Node) = {
    val session = UUID.fromString((xml \ "@session_id").text)
    val serial = BigInteger.valueOf((xml \ "@serial").text.toLong)
    val snapshot = (xml \ "snapshot" map { SnapshotReference.fromXml(_) }).toList.head
    val deltas = (xml \ "delta" map { DeltaReference.fromXml(_) }).toList

    Notification(session, serial, snapshot, deltas)
  }
}

sealed trait UpdatePath
case class UpdatePathWithSnapshot(snaphotRef: SnapshotReference) extends UpdatePath
case class UpdatePathWithDeltas(deltaRefs: List[DeltaReference]) extends UpdatePath

case class SnapshotReference(uri: URI, hash: ReferenceHash) {
  def retrieve = Snapshot.fromXml(XML.load(uri)) // TODO: check serial and hash
}

object SnapshotReference {
  def fromXml(xml: Node) = {
    val uri = URI.create((xml \ "@uri").text)
    val hash = ReferenceHash((xml \ "@hash").text)

    SnapshotReference(uri, hash)
  }
}

case class DeltaReference(uri: URI, serial: BigInteger, hash: ReferenceHash) {
  def retrieve = Deltas.fromXml(XML.load(uri)) // TODO: check from, to and hash
}

object DeltaReference {
  def fromXml(xml: Node) = {
    val uri = URI.create((xml \ "@uri").text)
    val serial = BigInteger.valueOf((xml \ "@serial").text.toLong)
    val hash = ReferenceHash((xml \ "@hash").text)

    DeltaReference(uri, serial, hash)
  }
}

case class Snapshot(sessionId: UUID, serial: BigInteger, publishes: List[Publish]) extends DeltaProtocolMessage
object Snapshot {
  def fromXml(xml: Node) = {
    val session = UUID.fromString((xml \ "@session_id").text)
    val serial = BigInteger.valueOf((xml \ "@serial").text.toLong)
    val publishes = (xml \ "publish" map { Publish.fromXml(_) }).toList

    Snapshot(session, serial, publishes)
  }
}

case class Deltas(sessionId: UUID, from: BigInteger, to: BigInteger, deltas: List[Delta]) extends DeltaProtocolMessage
object Deltas {
  def fromXml(xml: Node) = {
    val session = UUID.fromString((xml \ "@session_id").text)
    val from = BigInteger.valueOf((xml \ "@from").text.toLong)
    val to = BigInteger.valueOf((xml \ "@to").text.toLong)
    val deltas = ((xml \\ "deltas") \\ "delta").map(Delta.fromXml(_)).toList

    Deltas(session, from, to, deltas)
  }
}

case class Delta(serial: BigInteger, messages: List[PublicationProtocolMessage]) extends DeltaProtocolMessage
object Delta {
  def fromXml(xml: Node) = {
    val serial = BigInteger.valueOf((xml \ "@serial").text.toLong)
    val publishes = (xml \ "publish" map { Publish.fromXml(_) }).toList
    val withdraws = (xml \ "withdraw" map { Withdraw.fromXml(_) }).toList

    Delta(serial, publishes ++ withdraws)
  }
}

sealed trait PublicationProtocolMessage

case class Publish(uri: URI, replaces: Option[ReferenceHash], repositoryObject: CertificateRepositoryObject) extends PublicationProtocolMessage
object Publish {
  def fromXml(xml: Node) = {
    val uri = URI.create((xml \ "@uri").text)

    val repositoryObject = {
      val result = ValidationResult.withLocation(uri)
      val bytes = new BASE64Decoder().decodeBuffer(xml.text)
      CertificateRepositoryObjectFactory.createCertificateRepositoryObject(bytes, result)
    }

    val replaces = {
      val hash = (xml \ "@hash").text
      if (hash == null || hash.length == 0) {
        None
      } else {
        Some(ReferenceHash(hash = hash))
      }
    }

    Publish(uri, replaces, repositoryObject)
  }
}

case class Withdraw(uri: URI, hash: ReferenceHash) extends PublicationProtocolMessage
object Withdraw {
  def fromXml(xml: Node) = Withdraw(uri = URI.create((xml \ "@uri").text), hash = ReferenceHash((xml \ "@hash").text))
}