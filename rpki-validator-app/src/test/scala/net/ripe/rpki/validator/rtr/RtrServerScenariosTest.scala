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

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner
import java.net.Socket
import java.net.InetAddress
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.matchers.ShouldMatchers._
import java.io.PrintWriter
import java.io.DataOutputStream
import org.scalatest.BeforeAndAfter
import net.ripe.rpki.validator.lib.Port
import net.ripe.rpki.validator.models.Roas
import net.ripe.rpki.validator.models.TrustAnchors
import net.ripe.rpki.validator.config.Atomic
import net.ripe.rpki.validator.config.Database
import net.ripe.certification.validator.util.TrustAnchorLocator
import java.io.File
import java.net.URI
import net.ripe.rpki.validator.models.ValidatedRoa
import net.ripe.commons.certification.cms.roa._
import net.ripe.rpki.validator.models._
import scala.collection.mutable._
import net.ripe.ipresource.Ipv4Address
import net.ripe.ipresource.Asn
import net.ripe.ipresource.Ipv6Address
import scala.util.Random
import net.ripe.commons.certification.ValidityPeriod
import org.joda.time.DateTime

import scala.collection.JavaConverters._

@RunWith(classOf[JUnitRunner])
class RtrServerScenariosTest extends FunSuite with BeforeAndAfterAll with BeforeAndAfter with ShouldMatchers {

  val port = Port.any

  var server: RTRServer = null
  var client: RTRClient = null

  var cache: Atomic[Database] = null

  var nonce: Short = new Random().nextInt(65536).toShort

  override def beforeAll() = {
    var trustAnchors: TrustAnchors = new TrustAnchors(collection.mutable.Seq.empty[TrustAnchor])
    var validatedRoas: Roas = new Roas(new HashMap[String, Option[Seq[ValidatedRoa]]])
    cache = new Atomic(Database(trustAnchors, validatedRoas))
    server = new RTRServer(
      port = port,
      noCloseOnError = false,
      noNotify = false,
      getCurrentCacheSerial = { () => cache.get.version },
      getCurrentRoas = { () => cache.get.roas },
      getCurrentNonce = { () => nonce })
    server.startServer()
  }

  before {
    client = new RTRClient(port)
  }

  override def afterAll() = {
    server.stopServer()
  }

  after {
    cache.update {
      var trustAnchors: TrustAnchors = new TrustAnchors(collection.mutable.Seq.empty[TrustAnchor])
      var validatedRoas: Roas = new Roas(new HashMap[String, Option[Seq[ValidatedRoa]]])
      db => Database(trustAnchors, validatedRoas)
    }
    client.close()
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.1
  test("Server should answer with data to ResetQuery") {

    var file: File = new File("/tmp")
    var caName = "test ca"
    var location: URI = URI.create("rsync://example.com/")
    var publicKeyInfo = "info"
    var prefetchUris: java.util.List[URI] = new java.util.ArrayList[URI]()

    var tal: TrustAnchorLocator = new TrustAnchorLocator(file, caName, location, publicKeyInfo, prefetchUris)

    // TODO: use the method that allows explicit list of roa prefixes for testing

    val prefixes = List[RoaPrefix](
      RoaCmsObjectMother.TEST_IPV4_PREFIX_1,
      RoaCmsObjectMother.TEST_IPV4_PREFIX_2,
      RoaCmsObjectMother.TEST_IPV6_PREFIX,
      RoaCmsObjectMother.TEST_IPV6_PREFIX) // List IPv6 Prefix twice. It should be filtered when response is sent 

    val validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1))

    val roa: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes.asJava, validityPeriod, RoaCmsObjectMother.TEST_ASN)
    val roaUri: URI = URI.create("rsync://example.com/roa.roa")

    val validatedRoa: ValidatedRoa = new ValidatedRoa(roa, roaUri, tal)

    val roas = collection.mutable.Seq.apply[ValidatedRoa](validatedRoa)

    cache.update { db =>
      db.copy(roas = db.roas.update(tal, roas), version = db.version + 1)
    }

    client.sendPdu(ResetQueryPdu())
    var responsePdus = client.getResponse(expectedNumber = 5)
    responsePdus.size should equal(5)

    var iter = responsePdus.iterator

    iter.next() match {
      case CacheResponsePdu(responseNonce) => responseNonce should equal(nonce)
      case _ => fail("Should get cache response")
    }

    iter.next() match {
      case IPv4PrefixAnnouncePdu(start, length, maxLength, asn) =>
        start should equal(Ipv4Address.parse("10.64.0.0"))
        length should equal(12)
        maxLength should equal(24)
        asn should equal(Asn.parse("AS65000"))
      case _ => fail("Should get IPv4 Announce Pdu")
    }
    iter.next() match {
      case IPv4PrefixAnnouncePdu(start, length, maxLength, asn) =>
        start should equal(Ipv4Address.parse("10.32.0.0"))
        length should equal(12)
        maxLength should equal(12)
        asn should equal(Asn.parse("AS65000"))
      case _ => fail("Should get IPv4 Announce Pdu")
    }
    iter.next() match {
      case IPv6PrefixAnnouncePdu(start, length, maxLength, asn) =>
        start should equal(Ipv6Address.parse("2001:0:200::"))
        length should equal(39)
        maxLength should equal(39)
        asn should equal(Asn.parse("AS65000"))
      case _ => fail("Should get IPv6 Announce Pdu")

    }

    var lastSerial: Long = 0
    iter.next() match {
      case EndOfDataPdu(responseNonce, serial) =>
        responseNonce should equal(nonce)
        serial should equal(cache.get.version)
        lastSerial = serial
      case _ => fail("Expected end of data")
    }

    client.isConnected should be(true)

    // Send serial, should get response with no new announcements/withdrawals
    client.sendPdu(SerialQueryPdu(nonce = nonce, serial = lastSerial))

    var responsePdusBeforeNewRoas = client.getResponse(expectedNumber = 2)
    responsePdusBeforeNewRoas.size should equal(2)

    iter = responsePdusBeforeNewRoas.iterator
    iter.next() match {
      case CacheResponsePdu(responseNonce) => responseNonce should equal(nonce)
      case _ => fail("Should get cache response")
    }

    iter.next() match {
      case EndOfDataPdu(responseNonce, serial) =>
        responseNonce should equal(nonce)
        serial should equal(lastSerial)
      case _ => fail("Expected end of data")
    }

    client.isConnected should be(true)

    // Update ROAs, client should get notify
    cache.update { db =>
      db.copy(roas = db.roas.update(tal, roas), version = db.version + 1)
    }
    server.notify(cache.get.version)

    var responsePdusAfterCacheUpdate = client.getResponse(expectedNumber = 1)
    responsePdusAfterCacheUpdate.size should equal(1)
    responsePdusAfterCacheUpdate.head match {
      case SerialNotifyPdu(nonce, serial) =>
      case _ => fail("Should get serial notify")
    }

    // Send serial, should get reset response (we don't support incremental updates yet)
    client.sendPdu(SerialQueryPdu(nonce = nonce, serial = lastSerial))

    var responsePdusAfterNewRoas = client.getResponse(expectedNumber = 1)
    responsePdusAfterNewRoas.size should equal(1)
    responsePdusAfterNewRoas.head match {
      case CacheResetPdu() => // No content to check, we're good
      case _ => fail("Should get cache reset response")
    }
    client.isConnected should be(true)

  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.4
  test("Server should answer with No Data Available Error Pdu when RTRClient sends ResetQuery -- and there is no data") {
    client.sendPdu(ResetQueryPdu())
    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.NoDataAvailable)
    client.isConnected should be(true)
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with Invalid Request Error Pdu when RTRClient sends nonsense") {
    client.sendPdu(new ErrorPdu(errorCode = ErrorPdu.NoDataAvailable, Array.empty, ""))
    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.InvalidRequest)
    client.isConnected should be(false)
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with '5 - Unsupported PDU Type' when unsupported PDU type is sent") {
    client.sendData(Array[Byte](0x0, 0xff.toByte, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8))

    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.UnsupportedPduType)
    client.isConnected should be(false)
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with '4: Unsupported Protocol Version' when unsupported protocol is sent") {
    client.sendData(Array[Byte](0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8))
    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.UnsupportedProtocolVersion)
    client.isConnected should be(false)
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with CorruptData when PDU length less than 8") {
    client.sendData(Array[Byte](0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6))

    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.CorruptData)
    client.isConnected should be(false)
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with CorruptData when PDU length more than max frame length") {
    // 16777217 is one over frame length: in hex 01 00 00 01
    client.sendData(Array[Byte](0x0, 0x2, 0x0, 0x0, 0x1, 0x0, 0x0, 0x1) ++ Array.fill[Byte](RTRServer.MAXIMUM_FRAME_LENGTH + 1 - 8)(0))

    var responsePdus = client.getResponse()

    responsePdus.size should equal(1)
    var response = responsePdus.head

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdu.CorruptData)
    client.isConnected should be(false)
  }

}