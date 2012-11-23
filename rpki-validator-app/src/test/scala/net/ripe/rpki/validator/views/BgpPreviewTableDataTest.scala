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
package views

import net.ripe.rpki.validator.bgp.preview.BgpAnnouncement
import net.ripe.rpki.validator.bgp.preview.BgpValidatedAnnouncement
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import net.ripe.rpki.commons.validation.roa.RouteValidityState
import scala.collection.mutable.HashMap
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.rpki.validator.models.RtrPrefix

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class BgpPreviewControllerTest extends FunSuite with ShouldMatchers {
  import lib.NumberResourcesTest._

  val announce1 = BgpValidatedAnnouncement(BgpAnnouncement(65001, "10.0.0.0/24"), validates = Seq(RtrPrefix(65001, "10.0.0.0/24", None)), invalidates = Seq.empty)
  val announce2 = BgpValidatedAnnouncement(BgpAnnouncement(65002, "10.0.1.0/24"), validates = Seq.empty, invalidates = Seq(RtrPrefix(0, "10.0.1.0/24", None)))
  val announce3 = BgpValidatedAnnouncement(BgpAnnouncement(65003, "10.0.2.0/24"), validates = Seq.empty, invalidates = Seq.empty)

  val testAnnouncements: IndexedSeq[BgpValidatedAnnouncement] = IndexedSeq[BgpValidatedAnnouncement](announce1, announce2, announce3)

  val subject = new BgpPreviewTableData(testAnnouncements) {
    override def getParam(name: String) = "1"
  }

  test("Should filter overlapping IP resources") {
    val filteredAnnouncements = subject.filterRecords(testAnnouncements, IpRange.parse("10/23"))

    filteredAnnouncements should contain(announce1)
    filteredAnnouncements should contain(announce2)
    filteredAnnouncements should have length (2)
  }

  test("Should filter by ASN") {

    val filteredAnnouncements = subject.filterRecords(testAnnouncements, Asn.parse("AS65001"))

    filteredAnnouncements should contain(announce1)
    filteredAnnouncements should have length (1)

  }

}
