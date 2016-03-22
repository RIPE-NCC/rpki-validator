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
package rtr

import org.jboss.netty.buffer.ChannelBuffer
import org.jboss.netty.buffer.ChannelBuffers
import java.nio.ByteOrder
import net.ripe.ipresource._
import java.math.BigInteger
import scala.util.Random
import java.net.SocketAddress

sealed trait Pdu {
  def protocolVersion: Byte = 0
  def pduType: Byte
  def headerShort: Short = 0
  def length: Int

  def toPrettyContentString: String

  def toEncodedByteArray: Array[Byte] = {
    Pdus.encode(this)
  }
}

object Pdu {
  type SessionId = Short
  def randomSessionid = Random.nextInt(65536).toShort
}

case class BadData(errorCode: Int, content: Array[Byte])

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.1
 */
case class SerialNotifyPdu(sessionId: Pdu.SessionId, serial: Long) extends Pdu {
  override def pduType = PduTypes.SerialNotify
  override def headerShort = sessionId
  override def length = 12
  override def toPrettyContentString: String = "Serial Notify (session-id: " + sessionId + " , serial: " + serial + ")"

  assert(serial <= EndOfDataPdu.MAX_SERIAL)
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.2
 */
case class SerialQueryPdu(sessionId: Pdu.SessionId, serial: Long) extends Pdu {
  override def pduType = PduTypes.SerialQuery
  override def headerShort = sessionId
  override def length = 12
  override def toPrettyContentString: String = "Serial Query (session-id: " + sessionId + " , serial: " + serial + ")"

  assert(serial <= EndOfDataPdu.MAX_SERIAL)
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.3
 */
case class ResetQueryPdu() extends Pdu {
  override def pduType = PduTypes.ResetQuery
  override def length = 8
  override def toPrettyContentString: String = "Reset Query"
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.4
 */
case class CacheResponsePdu(sessionId: Pdu.SessionId) extends Pdu {
  override def pduType = PduTypes.CacheResponse
  override def headerShort = sessionId
  override def length = 8
  override def toPrettyContentString: String = "Cache Response (session-id: " + sessionId + ")"
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.5
 */
case class IPv4PrefixAnnouncePdu(ipv4PrefixStart: Ipv4Address, prefixLength: Byte, maxLength: Byte, asn: Asn) extends Pdu {
  override def pduType = PduTypes.IPv4Prefix
  override def length = 20
  override def toPrettyContentString: String = "Add IPv4 Prefix (prefix: " + ipv4PrefixStart + "/" + prefixLength + ", maxLength: " + maxLength + ", Asn: " + asn + ")"
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.6
 */
case class IPv6PrefixAnnouncePdu(ipv6PrefixStart: Ipv6Address, prefixLength: Byte, maxLength: Byte, asn: Asn) extends Pdu {
  override def pduType = PduTypes.IPv6Prefix
  override def length = 32
  override def toPrettyContentString: String = "Add IPv6 Prefix (prefix: " + ipv6PrefixStart + "/" + prefixLength + ", maxLength: " + maxLength + ", Asn: " + asn + ")"

}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.7
 */
case class EndOfDataPdu(sessionId: Pdu.SessionId, serial: Long) extends Pdu {
  override def pduType = PduTypes.EndOfData
  override def headerShort: Short = sessionId
  override def length = 12
  override def toPrettyContentString: String = "End of Data (session-id: " + sessionId + ", serial: " + serial + ")"

  assert(serial <= EndOfDataPdu.MAX_SERIAL)
}

object EndOfDataPdu {
  val MAX_SERIAL: Long = 4294967296L - 1
}

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-5.8
 */
case class CacheResetPdu() extends Pdu {
  override def pduType = PduTypes.CacheReset
  override def length = 8
  override def toPrettyContentString: String = "Cache Reset"
}

case class ErrorPdu(errorCode: Int, causingPdu: Array[Byte], errorText: String) extends Pdu {
  final override val pduType = PduTypes.Error
  override def headerShort = errorCode.toShort

  def causingPduLength = causingPdu.length

  val errorTextBytes: Array[Byte] = errorText.getBytes("UTF-8")
  val errorTextLength = errorTextBytes.length

  override val length = 8 + 4 + causingPduLength + 4 + errorTextLength

  override def toPrettyContentString: String = "Error (code: " + errorCode + ", description: " + errorText + ")"
}

object ErrorPdu {
  val CorruptData = 0
  val InternalError = 1
  val NoDataAvailable = 2
  val InvalidRequest = 3
  val UnsupportedProtocolVersion = 4
  val UnsupportedPduType = 5
  val WithdrawalOfUnkownRecord = 6
  val DuplicateAnnouncementReceived = 7

  def isFatal(errorCode: Int) = errorCode != NoDataAvailable

}

object PduTypes {
  val SerialNotify: Byte = 0
  val SerialQuery: Byte = 1
  val ResetQuery: Byte = 2
  val CacheResponse: Byte = 3
  val IPv4Prefix: Byte = 4
  val IPv6Prefix: Byte = 6
  val EndOfData: Byte = 7
  val CacheReset: Byte = 8
  val Error: Byte = 10
}

object Pdus {
  val SupportedProtocol: Byte = 0

  def encode(pdu: Pdu): Array[Byte] = {
    val buffer = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, pdu.length)
    buffer.writeByte(pdu.protocolVersion)
    buffer.writeByte(pdu.pduType)
    buffer.writeShort(pdu.headerShort)
    buffer.writeInt(pdu.length)

    pdu match {
      case SerialNotifyPdu(_, serial) => buffer.writeInt(serial.toInt)
      case SerialQueryPdu(_, serial) => buffer.writeInt(serial.toInt)
      case errorPdu @ ErrorPdu(errorCode, causingPdu, errorText) => writeErrorPduPayload(buffer, errorPdu, causingPdu)
      case ResetQueryPdu() => // no payload
      case CacheResponsePdu(_) => // no payload (sessionId is in header)
      case IPv4PrefixAnnouncePdu(prefix, length, maxLength, asn) => writeIPv4PrefixAnnouncePduPayload(buffer, prefix, length, maxLength, asn)
      case IPv6PrefixAnnouncePdu(prefix, length, maxLength, asn) => writeIPv6PrefixAnnouncePduPayload(buffer, prefix, length, maxLength, asn)
      case EndOfDataPdu(_, serial) => buffer.writeInt(serial.toInt)
      case CacheResetPdu() => // no payload
    }

    buffer.array()
  }

  def fromByteArray(buffer: ChannelBuffer): Either[BadData, Pdu] = try {
    val protocol = buffer.readByte()
    val pduType = buffer.readByte()
    val headerShort = buffer.readShort()
    val length = buffer.readInt()

    if (protocol != SupportedProtocol) {
      Left(BadData(ErrorPdu.UnsupportedProtocolVersion, buffer.array))
    } else {
      pduType match {
        case PduTypes.SerialNotify => parseSerialNotifyPdu(buffer, headerShort)
        case PduTypes.SerialQuery => parseSerialQueryPdu(buffer, headerShort)
        case PduTypes.Error => parseErrorPdu(buffer, headerShort)
        case PduTypes.ResetQuery => Right(ResetQueryPdu())
        case PduTypes.CacheResponse => parseCacheResponsePdu(headerShort)
        case PduTypes.EndOfData => parseEndOfDataPdu(buffer, headerShort)
        case PduTypes.IPv4Prefix => parseIPv4PrefixPdu(buffer)
        case PduTypes.IPv6Prefix => parseIPv6PrefixPdu(buffer)
        case PduTypes.CacheReset => Right(CacheResetPdu())
        case _ => Left(BadData(ErrorPdu.UnsupportedPduType, buffer.array))
      }
    }
  } catch {
    case e: IndexOutOfBoundsException =>
      Left(BadData(ErrorPdu.CorruptData, buffer.array()))
  }

  private def convertToPrependedByteArray(value: BigInteger, bytesNeeded: Int): Array[Byte] = {
    var valueBytes = value.toByteArray

    // sometimes we get extra zero bytes in front... strange... what am I missing? Sign bit?

    if (valueBytes.size > 1 && valueBytes.head == 0) valueBytes = valueBytes.drop(1)

    var extraBytesNeeded = bytesNeeded - valueBytes.length
    var prependBytes = new Array[Byte](extraBytesNeeded)
    prependBytes ++ valueBytes
  }

  private def writeErrorPduPayload(buffer: ChannelBuffer, errorPdu: ErrorPdu, causingPdu: Array[Byte]): Unit = {
    buffer.writeInt(causingPdu.length)
    buffer.writeBytes(causingPdu)
    buffer.writeInt(errorPdu.errorTextBytes.length)
    buffer.writeBytes(errorPdu.errorTextBytes)
  }

  private def writeIPv4PrefixAnnouncePduPayload(buffer: ChannelBuffer, prefix: Ipv4Address, length: Byte, maxLength: Byte, asn: Asn): Unit = {
    buffer.writeByte(1)
    buffer.writeByte(length)
    buffer.writeByte(maxLength)
    buffer.writeByte(0)
    buffer.writeBytes(convertToPrependedByteArray(prefix.getValue, 4))
    buffer.writeBytes(convertToPrependedByteArray(asn.getValue, 4))
  }

  private def writeIPv6PrefixAnnouncePduPayload(buffer: ChannelBuffer, prefix: Ipv6Address, length: Byte, maxLength: Byte, asn: Asn): Unit = {
    buffer.writeByte(1)
    buffer.writeByte(length)
    buffer.writeByte(maxLength)
    buffer.writeByte(0)
    buffer.writeBytes(convertToPrependedByteArray(prefix.getValue, 16))
    buffer.writeBytes(convertToPrependedByteArray(asn.getValue, 4))
  }

  private def parseSerialNotifyPdu(buffer: ChannelBuffer, sessionId: Pdu.SessionId): Right[Nothing, SerialNotifyPdu] = {
    val serial = buffer.readUnsignedInt()
    Right(SerialNotifyPdu(sessionId, serial))
  }

  private def parseSerialQueryPdu(buffer: ChannelBuffer, sessionId: Pdu.SessionId): Right[Nothing, SerialQueryPdu] = {
    val serial = buffer.readUnsignedInt()
    Right(SerialQueryPdu(sessionId, serial))
  }

  private def parseErrorPdu(buffer: ChannelBuffer, headerShort: Short): Right[Nothing, ErrorPdu] = {
    val causingPduLength = buffer.readInt()
    val causingPdu = buffer.readBytes(causingPduLength).array()
    val errorTextLength = buffer.readInt()
    val errorTextBytes = buffer.readBytes(errorTextLength)
    val errorText = new String(buffer.array(), "UTF-8")
    Right(ErrorPdu(headerShort, causingPdu, errorText))
  }

  private def parseCacheResponsePdu(sessionId: Pdu.SessionId): Right[Nothing, CacheResponsePdu] = {
    Right(CacheResponsePdu(sessionId))
  }

  private def parseEndOfDataPdu(buffer: ChannelBuffer, sessionId: Pdu.SessionId): Right[Nothing, EndOfDataPdu] = {
    val serial = buffer.readUnsignedInt()
    Right(EndOfDataPdu(sessionId, serial))
  }

  private def parseIPv4PrefixPdu(buffer: ChannelBuffer): Either[BadData, Pdu] = {
    buffer.readByte() match {
      case 1 =>
        val length = buffer.readByte()
        val maxLenght = buffer.readByte()
        buffer.skipBytes(1)
        val prefix = new Ipv4Address(buffer.readUnsignedInt())
        val asn = new Asn(buffer.readUnsignedInt())
        Right(IPv4PrefixAnnouncePdu(prefix, length, maxLenght, asn))
      case _ =>
        // TODO: Support withdrawals
        Left(BadData(ErrorPdu.UnsupportedPduType, buffer.array))
    }
  }
  private def parseIPv6PrefixPdu(buffer: ChannelBuffer): Either[BadData, Pdu] = {
    buffer.readByte() match {
      case 1 =>
        val length = buffer.readByte()
        val maxLenght = buffer.readByte()
        buffer.skipBytes(1)
        val ipv6Bytes: Array[Byte] = new Array[Byte](16)
        buffer.getBytes(12, ipv6Bytes)
        val prefix = new Ipv6Address(new BigInteger(1, ipv6Bytes)) // Careful, omit sign and bad things happen when calling equals

        buffer.skipBytes(16)
        val asn = new Asn(buffer.readUnsignedInt())
        Right(IPv6PrefixAnnouncePdu(prefix, length, maxLenght, asn))
      case _ =>
        // TODO: Support withdrawals
        Left(BadData(ErrorPdu.UnsupportedPduType, buffer.array))
    }
  }
}

case class RtrPduLogEntry(childAddress: SocketAddress, data: Either[BadData, Pdu], sender: Sender) {
  override def toString = {
    val direction = sender match {
      case Server => "<-"
      case Client => "->"
    }

    def prettyPrintByteArray(array: Array[Byte]) = array.map(_.formatted("%02X")).mkString(" ")

    val description = data match {
      case Left(badData) => ("Unparsable Data", prettyPrintByteArray(badData.content))
      case Right(pdu) => (pdu.toPrettyContentString, prettyPrintByteArray(pdu.toEncodedByteArray))
    }

    childAddress + " " + direction + " " + description._1 + ", hex: " + description._2
  }
}