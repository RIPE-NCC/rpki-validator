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
package controllers

import java.io.File
import java.net.URI
import java.util.Collections

import net.ripe.ipresource.{Asn, IpRange}
import net.ripe.rpki.validator.models.RtrPrefix
import net.ripe.rpki.validator.support.ControllerTestCase
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.format.ISODateTimeFormat
import org.joda.time.{DateTime, DateTimeUtils}
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class ExportControllerTest extends ControllerTestCase {

  val tal = new TrustAnchorLocator(new File(""),
                                   "Ca Name",
                                   Collections.singletonList(URI.create("rsync://rpki.ripe.net/root.cer")),
                                   "publicKeyInfo",
                                   Collections.emptyList())
  val PREFIX1 = RtrPrefix(asn = Asn.parse("AS6500"), prefix = IpRange.parse("10/8"), maxPrefixLength = None, Some(tal))
  val PREFIX2 = RtrPrefix(asn = Asn.parse("AS6501"), prefix = IpRange.parse("10/16"), maxPrefixLength = Some(18))
  val PREFIX3 = RtrPrefix(asn = Asn.parse("AS6502"), prefix = IpRange.parse("2001:43e8::/32"), maxPrefixLength = Some(32), Some(tal))
  val TEST_PREFIXES = Set[RtrPrefix](PREFIX1, PREFIX2, PREFIX3)

  override def controller = new ControllerFilter with ExportController {
    override def getRtrPrefixes: Seq[RtrPrefix] = TEST_PREFIXES.toSeq
  }

  test("Should make CSV with max lengths filled out") {
    get("/export.csv") {

      val expectedResponse =
        """ASN,IP Prefix,Max Length,Trust Anchor
          |AS6500,10.0.0.0/8,8,Ca Name
          |AS6501,10.0.0.0/16,18,unknown
          |AS6502,2001:43e8::/32,32,Ca Name
          |""".stripMargin

      status should equal(200)
      body should equal(expectedResponse)
      header("Content-Type").toLowerCase() should startWith("text/csv")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      header("Pragma") should equal("public")
      header("Cache-Control") should equal("no-cache")
    }
  }

  test("Should export JSON with max lengths filled out") {
    get("/export.json") {
      status should equal(200)
      body should equal("""{"roas":[{"asn":"AS6500","prefix":"10.0.0.0/8","maxLength":8,"ta":"Ca Name"},{"asn":"AS6501","prefix":"10.0.0.0/16","maxLength":18,"ta":"unknown"},{"asn":"AS6502","prefix":"2001:43e8::/32","maxLength":32,"ta":"Ca Name"}]}""")
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      header("Pragma") should equal("public")
      header("Cache-Control") should equal("no-cache")
    }
  }

  test("Should make rpsl for every possible route") {
    val dateTime = DateTime.now
    DateTimeUtils.setCurrentMillisFixed(dateTime.getMillis)
    val formattedDateTime = ISODateTimeFormat.dateTimeNoMillis().withZoneUTC().print(dateTime)

    get("/export.rpsl") {

      val expectedResponse =
        s"""
         |route: 10.0.0.0/8
         |origin: AS6500
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-CA-NAME
         |
         |route: 10.0.0.0/16
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.0.0/17
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.0.0/18
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.64.0/18
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.128.0/17
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.128.0/18
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route: 10.0.192.0/18
         |origin: AS6501
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-UNKNOWN
         |
         |route6: 2001:43e8::/32
         |origin: AS6502
         |descr: exported from ripe ncc validator
         |mnt-by: NA
         |created: $formattedDateTime
         |last-modified: $formattedDateTime
         |source: ROA-CA-NAME
         |""".stripMargin

      status should equal(200)
      body should equal(expectedResponse)
      header("Content-Type").toLowerCase() should startWith("text/plain")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      header("Pragma") should equal("public")
      header("Cache-Control") should equal("no-cache")
    }
  }

}
