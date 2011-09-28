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
package net.ripe.rpki.validator.rtr

import org.scalatest.FunSuite
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.Charset
import org.scalatest.matchers.ShouldMatchers
import org.jboss.netty.buffer.BigEndianHeapChannelBuffer

import net.ripe.ipresource._

@RunWith(classOf[JUnitRunner])
class PduTest extends FunSuite with ShouldMatchers {

  test("convert to byte array an ErrorPdu without causingPdu nor errorText") {
    val bytes = Pdus.encode(PduTest.NoDataAvailablePdu)
    bytes should equal(PduTest.NoDataAvailablePduBytes)
  }

  test("should convert reset pdu to byte array and back") {
    val resetPdu = new ResetQueryPdu()
    val expectedBytes = Array[Byte](0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8)
    val bytes = Pdus.encode(resetPdu)

    bytes should equal(expectedBytes)

    Pdus.fromByteArray(new BigEndianHeapChannelBuffer(bytes)) match {
      case Right(decodedPdu: ResetQueryPdu) =>
        decodedPdu should equal(resetPdu)
      case _ => fail("Got back a wrong response")
    }
  }

  test("should convert cache response pdu to byte array and back") {
    val cacheResponsePdu = new CacheResponsePdu(nonce = 0)
    val expectedBytes = Array[Byte](0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8)
    val bytes = Pdus.encode(cacheResponsePdu)

    bytes should equal(expectedBytes)

    Pdus.fromByteArray(new BigEndianHeapChannelBuffer(bytes)) match {
      case Right(decodedPdu: CacheResponsePdu) =>
        decodedPdu should equal(cacheResponsePdu)
      case _ => fail("Got back a wrong response")
    }
  }

  test("should convert ipv4 prefix announce pdu to byte array and back") {
    val ipv4PrefixPdu = new IPv4PrefixAnnouncePdu(Ipv4Address.parse("10.0.0.0"), 8, 10, Asn.parse("65535"))
    val expectedBytes = Array[Byte](0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0x1, 0x8, 0xa, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 255.toByte, 255.toByte)
    val bytes = Pdus.encode(ipv4PrefixPdu)

    bytes should equal(expectedBytes)

    Pdus.fromByteArray(new BigEndianHeapChannelBuffer(bytes)) match {
      case Right(decodedPdu: IPv4PrefixAnnouncePdu) =>
        decodedPdu should equal(ipv4PrefixPdu)
      case _ => fail("Got back a wrong response")
    }
  }

  test("should convert ipv6 prefix announce pdu to byte array and back") {
    val ipv6PrefixPdu = new IPv6PrefixAnnouncePdu(Ipv6Address.parse("fc00::"), 7, 10, Asn.parse("65535"))
    val expectedBytes = Array[Byte](0x0, 0x6, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x20,
      0x1, 0x7, 0xa, 0x0,
      252.toByte, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 0x0, 0x0,
      0x0, 0x0, 255.toByte, 255.toByte)
    val bytes = Pdus.encode(ipv6PrefixPdu)

    bytes should equal(expectedBytes)

    Pdus.fromByteArray(new BigEndianHeapChannelBuffer(bytes)) match {
      case Right(decodedPdu: IPv6PrefixAnnouncePdu) =>
        decodedPdu should equal(ipv6PrefixPdu)
      case _ => fail("Got back a wrong response")
    }
  }

}

object PduTest {
  val NoDataAvailablePduBytes = Array[Byte](0x0, 0xa, 0x0, 0x2, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
  val NoDataAvailablePdu = ErrorPdu(ErrorPdu.NoDataAvailable, Array.empty, "")
}
