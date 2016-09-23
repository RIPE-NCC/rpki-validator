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

import java.io.File
import java.net.URI
import java.util.Collections

import net.ripe.ipresource.{Asn, Ipv4Address, Ipv6Address}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.roa._
import net.ripe.rpki.commons.validation.ValidationCheck
import net.ripe.rpki.validator.config._
import net.ripe.rpki.validator.lib._
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.support.ValidatorTestCase
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.DateTime
import org.junit.runner.RunWith
import org.scalatest.{BeforeAndAfter, BeforeAndAfterAll}
import org.scalatest.junit.JUnitRunner

import scala.collection.JavaConverters._
import scala.util.Random

@RunWith(classOf[JUnitRunner])
class RtrServerScenariosTest extends ValidatorTestCase with BeforeAndAfterAll with BeforeAndAfter {

  val port = Port.any

  var server: RTRServer = null
  var client: RTRClient = null

  var cache: scala.concurrent.stm.Ref[MemoryImage] = null

  var sessionId: Short = new Random().nextInt(65536).toShort
  var tal: TrustAnchorLocator = null

  var hasTrustAnchors: Boolean = true

  override def beforeAll() = {
    implicit val actorSystem = akka.actor.ActorSystem()
    var file: File = new File("/tmp")
    var caName = "test ca"
    var location: URI = URI.create("rsync://example.com/")
    var publicKeyInfo = "info"
    var prefetchUris: java.util.List[URI] = new java.util.ArrayList[URI]()
    tal = new TrustAnchorLocator(file, caName, Collections.singletonList(location), publicKeyInfo, prefetchUris)
    val trustAnchors: TrustAnchors = new TrustAnchors(Seq(TrustAnchor(
      locator = tal,
      status = Idle(new DateTime, None),
      enabled = true)))
    val validatedObjects: ValidatedObjects = new ValidatedObjects(Map.empty)
    cache = scala.concurrent.stm.Ref(MemoryImage(Filters(), Whitelist(), trustAnchors, validatedObjects))
    server = new RTRServer(
      port = port,
      closeOnError = true,
      sendNotify = true,
      getCurrentCacheSerial = { () => cache.single.get.version },
      getCurrentRtrPrefixes = { () => cache.single.get.getDistinctRtrPrefixes },
      getCurrentSessionId = { () => sessionId },
      hasTrustAnchorsEnabled = { () => hasTrustAnchors }
    )
    server.startServer()
  }

  before {
    client = new RTRClient(port)
    hasTrustAnchors = true
  }

  override def afterAll() = {
    server.stopServer()
  }

  after {
    cache.single.transform {
      db => MemoryImage(Filters(), Whitelist(), new TrustAnchors(Seq.empty), new ValidatedObjects(Map.empty))
    }
    client.close()
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.1
  test("Server should answer with data to ResetQuery") {


    // TODO: use the method that allows explicit list of roa prefixes for testing

    val prefixes = List[RoaPrefix](
      RoaCmsObjectMother.TEST_IPV4_PREFIX_1,
      RoaCmsObjectMother.TEST_IPV4_PREFIX_2,
      RoaCmsObjectMother.TEST_IPV6_PREFIX,
      RoaCmsObjectMother.TEST_IPV6_PREFIX) // List IPv6 Prefix twice. It should be filtered when response is sent

    val validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1))

    val roa: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes.asJava, validityPeriod, RoaCmsObjectMother.TEST_ASN)
    val roaUri: URI = URI.create("rsync://example.com/roa.roa")

    val validatedRoa = new ValidObject("roa", roaUri, Some(Array[Byte](6)), Set.empty[ValidationCheck], roa)

    val roas = Seq(validatedRoa)

    cache.single.transform { db => db.updateValidatedObjects(tal, roas) }

    client.sendPdu(ResetQueryPdu())
    var responsePdus = client.getResponse(expectedNumber = 5)
    responsePdus.size should equal(5)

    var iter = responsePdus.iterator

    iter.next() match {
      case CacheResponsePdu(responseSessionId) => responseSessionId should equal(sessionId)
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
      case EndOfDataPdu(responseSessionId, serial) =>
        responseSessionId should equal(sessionId)
        serial should equal(cache.single.get.version)
        lastSerial = serial
      case _ => fail("Expected end of data")
    }

    client.isConnected should be(true)

    // Send serial, should get response with no new announcements/withdrawals
    client.sendPdu(SerialQueryPdu(sessionId = sessionId, serial = lastSerial))

    var responsePdusBeforeNewRoas = client.getResponse(expectedNumber = 2)
    responsePdusBeforeNewRoas.size should equal(2)

    iter = responsePdusBeforeNewRoas.iterator
    iter.next() match {
      case CacheResponsePdu(responseSessionId) => responseSessionId should equal(sessionId)
      case _ => fail("Should get cache response")
    }

    iter.next() match {
      case EndOfDataPdu(responseSessionId, serial) =>
        responseSessionId should equal(sessionId)
        serial should equal(lastSerial)
      case _ => fail("Expected end of data")
    }

    client should be ('connected)

    // Update ROAs, client should get notify
    cache.single.transform { db => db.updateValidatedObjects(tal, roas) }
    server.notify(cache.single.get.version)

    var responsePdusAfterCacheUpdate = client.getResponse(expectedNumber = 1)
    responsePdusAfterCacheUpdate.size should equal(1)
    responsePdusAfterCacheUpdate.head match {
      case SerialNotifyPdu(sessionId, serial) =>
      case _ => fail("Should get serial notify")
    }

    // Send serial, should get reset response (we don't support incremental updates yet)
    client.sendPdu(SerialQueryPdu(sessionId = sessionId, serial = lastSerial))

    var responsePdusAfterNewRoas = client.getResponse(expectedNumber = 1)
    responsePdusAfterNewRoas.size should equal(1)
    responsePdusAfterNewRoas.head match {
      case CacheResetPdu() => // No content to check, we're good
      case _ => fail("Should get cache reset response")
    }
    client should be ('connected)
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
    client should be ('connected)
  }

  test("Server should answer with data if no trust anchor exists/is enabled and there is not data") {
    hasTrustAnchors = false
    client.sendPdu(ResetQueryPdu())
    val response = client.getResponse(expectedNumber = 2)
    response.size should be(2)

    response match {
      case CacheResponsePdu(sId1) :: EndOfDataPdu(sId2, serial) :: nil =>
        sId1 should be(sessionId)
        sId2 should be(sessionId)
        serial should be(0)
      case _ => fail("Wrong response is received: " + response)
    }
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
    client should not be ('connected)
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
    client should not be ('connected)
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
    client should not be ('connected)
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
    client should not be ('connected)
  }
}
