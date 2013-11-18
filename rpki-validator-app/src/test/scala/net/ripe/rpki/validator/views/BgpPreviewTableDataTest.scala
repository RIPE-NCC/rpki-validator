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
import net.ripe.rpki.validator.models.RtrPrefix
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import net.ripe.rpki.validator.support.ValidatorTestCase

@RunWith(classOf[JUnitRunner])
class BgpPreviewTableDataTest extends ValidatorTestCase {
  import lib.NumberResourcesTest._

  val validAnnouncement = BgpValidatedAnnouncement(BgpAnnouncement(65001, "10.0.0.0/24"), valids = Seq(RtrPrefix(65001, "10.0.0.0/24")), invalidsLength = Seq(RtrPrefix(65001, "10.0.0.0/16", Some(20))))
  val invalidAsnAnnouncement = BgpValidatedAnnouncement(BgpAnnouncement(65002, "10.0.1.0/24"), invalidsAsn = Seq(RtrPrefix(65001, "10.0.1.0/24")))
  val invalidLengthAnnouncement = BgpValidatedAnnouncement(BgpAnnouncement(65003, "10.0.2.0/24"), invalidsAsn = Seq(RtrPrefix(65001, "10.0.2.0/24")), invalidsLength = Seq(RtrPrefix(65003, "10.0.0.0/16", Some(20))))
  val unknownAnnouncement = BgpValidatedAnnouncement(BgpAnnouncement(65004, "10.0.3.0/24"))

  val announcements = IndexedSeq(validAnnouncement, invalidAsnAnnouncement, invalidLengthAnnouncement, unknownAnnouncement)

  val subject = new BgpPreviewTableData(announcements) {
    override def getParam(name: String) = "1"
  }

  test("Should match IP resources or overlapping IP resources") {
    subject.filterRecords(announcements, "10.0.0.0/23": IpRange) should (have size 2 and contain(validAnnouncement) and contain(invalidAsnAnnouncement))
  }

  test("Should match AS number") {
    subject.filterRecords(announcements, "AS65001": String) should(have size 1 and contain(validAnnouncement))
    subject.filterRecords(announcements, "AS65001": Asn) should(have size 1 and contain(validAnnouncement))
  }

  test("Should match various keywords (ignoring case)") {
    subject.filterRecords(announcements, "vAlId") should(have size 1 and contain(validAnnouncement))
    subject.filterRecords(announcements, "UnknoWn") should(have size 1 and contain(unknownAnnouncement))
    subject.filterRecords(announcements, "InvaliD") should(have size 2 and contain(invalidAsnAnnouncement) and contain(invalidLengthAnnouncement))
    subject.filterRecords(announcements, "InvaliD ASN") should(have size 1 and contain(invalidAsnAnnouncement))
    subject.filterRecords(announcements, "InvaliD Length") should(have size 1 and contain(invalidLengthAnnouncement))
  }
}
