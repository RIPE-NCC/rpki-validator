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
package net.ripe.rpki.validator.bgp.preview

import org.scalatest.FunSuite
import org.scalatest.BeforeAndAfterAll
import org.scalatest.BeforeAndAfter
import org.scalatest.matchers.ShouldMatchers
import net.ripe.ipresource._
import java.net.URL

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class BgpRisDumpTest extends FunSuite with ShouldMatchers {

  test("should parse empty line") {
    BgpRisDump.parseLine("") should equal(None)
    BgpRisDump.parseLine("\n") should equal(None)
  }

  test("should parse comment line") {
    BgpRisDump.parseLine("% this is some comment") should equal(None)
  }

  test("should parse IPv4 announcement") {
    val entry = BgpRisDump.parseLine("3333\t127.0.0.0/8\t201\n")
    entry should equal(Some(new BgpRisEntry(origin = new Asn(3333), prefix = IpRange.parse("127.0.0.0/8"), visibility = 201)))
  }

  test("should parse IPv6 announcement") {
    val entry = BgpRisDump.parseLine("24490\t2001:254:8000::/33\t62\n")
    entry should equal(Some(new BgpRisEntry(origin = new Asn(24490), prefix = IpRange.parse("2001:254:8000::/33"), visibility = 62)))
  }

  test("should parse IPv4-Embedded Ipv6 announcement") {
    val entry = BgpRisDump.parseLine("24490\t::1.2.3.4/128\t62\n")
    entry should equal(Some(new BgpRisEntry(origin = new Asn(24490), prefix = IpRange.parse("::1.2.3.4/128"), visibility = 62)))
  }

  test("should skip malformed line") {
    val entry = BgpRisDump.parseLine("24490\t::::/128\t62\n")
    entry should equal(None)
  }

  test("should parse file") {
    val url = Thread.currentThread().getContextClassLoader().getResourceAsStream("ris/riswhoisdump-example.IPv4.gz")

    val entries = BgpRisDump.parseRisDump(url).right.get
    entries.size should equal (42 * 2) /// and don't ask why!
    entries should contain (new BgpRisEntry(origin = new Asn(45528), prefix = IpRange.parse("1.22.120.0/24"), visibility = 105))
  }

}
