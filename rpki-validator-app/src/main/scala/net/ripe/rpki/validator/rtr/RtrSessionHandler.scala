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
package net.ripe.rpki.validator.rtr

import net.ripe.ipresource.{Ipv6Address, Ipv4Address, Asn, IpRange}
import net.ripe.rpki.validator.models.RtrPrefix
import java.net.InetSocketAddress
import net.ripe.rpki.validator.lib.ValueAndTime
import org.jboss.netty.handler.codec.frame.{TooLongFrameException, CorruptedFrameException}
import org.jboss.netty.handler.timeout.ReadTimeoutException

class RtrSessionHandler[T] (remoteAddress: T,
                        getCurrentCacheSerial: () => Int,
                        getCurrentRtrPrefixes: () => Seq[RtrPrefix],
                        getCurrentSessionId: () => Pdu.SessionId,
                        hasTrustAnchorsEnabled: () => Boolean) {

  // assume we only get InetSocketAddress; other types will thow exception
  val sessionData = new RtrSessionData(remoteAddress.asInstanceOf[InetSocketAddress])


  def    connect() { sessionData.connected(true) }
  def disconnect() { sessionData.connected(false)}
  def serialNotify(pdu: Pdu) { sessionData.lastPduSent = pdu }

  def processRequest(request: Either[BadData, Pdu]): Seq[Pdu] = {
    request match {
      case Left(BadData(errorCode, content)) =>
        handleBadData(errorCode, content)
      case Right(pdu) =>
        val result = processRequestPdu(pdu)
        sessionData.lastPduSent = result.last
        result
    }
  }

  def determineErrorPdu(cause: Throwable): ErrorPdu = {
    sessionData.lastPduReceived_=(cause.getMessage)
    val result = cause match {
      case cause: CorruptedFrameException => ErrorPdu(ErrorPdu.CorruptData, Array.empty, cause.toString)
      case cause: TooLongFrameException => ErrorPdu(ErrorPdu.CorruptData, Array.empty, cause.toString)
      case cause: ReadTimeoutException => ErrorPdu(ErrorPdu.InternalError, Array.empty, "Connection timed out")
      case cause => ErrorPdu(ErrorPdu.InternalError, Array.empty, cause.toString)
    }
    sessionData.lastPduSent = result
    result
  }

  private def handleBadData(errorCode: Int, content: Array[Byte]): List[Pdu] = {
    sessionData.lastPduReceived = "Bad data (error code: %d)".format(errorCode)
    val pdu = ErrorPdu(errorCode, content, "")
    sessionData.lastPduSent = pdu
    List(pdu)
  }

  private def processRequestPdu(pdu: Pdu) = {
    pdu match {
      case ResetQueryPdu() =>
        sessionData.lastPduReceived = "ResetQuery"
        processResetQuery
      case SerialQueryPdu(sessionId, serial) =>
        sessionData.lastPduReceived = "SerialQuery"
        processSerialQuery(sessionId, serial)
      case _ =>
        sessionData.lastPduReceived = "Invalid Request"
        List(ErrorPdu(ErrorPdu.InvalidRequest, Array.empty, ""))
    }
  }

  private def processResetQuery: Seq[Pdu] = {
    (getCurrentCacheSerial(), hasTrustAnchorsEnabled()) match {
      case (0, true) => List(ErrorPdu(ErrorPdu.NoDataAvailable, Array.empty, ""))
      case (serialNumber, _) =>
        var responsePdus: Vector[Pdu] = Vector.empty
        val currentSessionId = getCurrentSessionId()
        responsePdus = responsePdus :+ CacheResponsePdu(sessionId = currentSessionId)

        getCurrentRtrPrefixes().foreach { rtrPrefix =>

          val prefix: IpRange = rtrPrefix.prefix
          val prefixLength: Int = prefix.getPrefixLength
          val maxLength: Int = rtrPrefix.maxPrefixLength.getOrElse(prefixLength)
          val asn: Asn = rtrPrefix.asn

          prefix.getStart match {
            case ipv4: Ipv4Address =>
              responsePdus = responsePdus :+ IPv4PrefixAnnouncePdu(ipv4, prefixLength.toByte, maxLength.toByte, asn)
            case ipv6: Ipv6Address =>
              responsePdus = responsePdus :+ IPv6PrefixAnnouncePdu(ipv6, prefixLength.toByte, maxLength.toByte, asn)
            case _ => assert(false)
          }
        }
        responsePdus :+ EndOfDataPdu(sessionId = currentSessionId, serial = serialNumber)
    }
  }


  private def processSerialQuery(sessionId: Short, serial: Long) = {
    if (sessionId == getCurrentSessionId() && serial == getCurrentCacheSerial()) {
      List(CacheResponsePdu(sessionId = sessionId), EndOfDataPdu(sessionId = sessionId, serial = serial))
    } else {
      List(CacheResetPdu())
    }
  }
}

class RtrSessionData(val remoteAddr: InetSocketAddress) {
  var connected: ValueAndTime[Boolean] = new ValueAndTime[Boolean](true){}
  var lastPduSent: Option[ValueAndTime[Pdu]] = None
  var lastPduReceived: Option[ValueAndTime[String]] = None
  
  def lastPduSent_=(pdu: Pdu) {
    lastPduSent = Some(new ValueAndTime[Pdu](pdu) {})
  }

  def lastPduReceived_=(pduType: String) {
    lastPduReceived = Some(new ValueAndTime[String](pduType) {})
  }

}
