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

@RunWith(classOf[JUnitRunner])
class ScenarioSuiteTest extends FunSuite with BeforeAndAfterAll with ShouldMatchers {

  override def beforeAll() = {
    RTRServer.startServer
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.4
  test("Server should answer with No Data Available Error Pdu when RTRClient sends Serial Query -- and there is no data") {
    val client = new RTRClient(8282)
    var response = client.sendPdu(new ResetQueryPdu)

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdus.NoDataAvailable)

    client.close
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with Invalid Reques Error Pdu when RTRClient sends nonsense") {
    val client = new RTRClient(8282)
    var response = client.sendPdu(new ErrorPdu(errorCode = 2, None, None))

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdus.InvalidRequest)

    client.close
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with '5 - Unsupported PDU Type' when unsupported Pdu is sent") {

    val client = new RTRClient(8282)
    val response = client.sendPdu(new UnknownPdu(Array[Byte](0x0, 0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8)))

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdus.UnsupportedPduType)

    client.close
  }

  // See: http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-10
  test("Server should answer with '4: Unsupported Protocol Version' when unsupported protocol is sent") {

    val client = new RTRClient(8282)
    val response = client.sendPdu(new UnknownPdu(Array[Byte](0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8)))

    assert(response.isInstanceOf[ErrorPdu])
    val errorPdu = response.asInstanceOf[ErrorPdu]
    errorPdu.errorCode should equal(ErrorPdus.UnsupportedProtocolVersion)

    client.close
  }

}