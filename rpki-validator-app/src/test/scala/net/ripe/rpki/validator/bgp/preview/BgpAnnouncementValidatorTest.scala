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
package bgp.preview

import org.scalatest.FunSuite
import org.scalatest.BeforeAndAfterAll
import org.scalatest.BeforeAndAfter
import org.scalatest.matchers.ShouldMatchers
import models.RtrPrefix
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import scalaz.concurrent.Promise

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class BgpAnnouncementValidatorTest extends FunSuite with BeforeAndAfterAll with ShouldMatchers {

  val AS1 = Asn.parse("AS65001")
  val AS2 = Asn.parse("AS65002")
  val AS3 = Asn.parse("AS65003")

  val PREFIX1 = IpRange.parse("10.0.1.0/24")
  val PREFIX2 = IpRange.parse("10.0.2.0/24")
  val PREFIX3 = IpRange.parse("10.0.3.0/24")
  val PREFIX4 = IpRange.parse("10.0.4.0/24")

  val ANNOUNCED_ROUTE1 = BgpAnnouncement(AS1, PREFIX1)
  val ANNOUNCED_ROUTE2 = BgpAnnouncement(AS2, PREFIX2)
  val ANNOUNCED_ROUTE3 = BgpAnnouncement(AS3, PREFIX4)

  val RTR_PREFIX1 = RtrPrefix(asn = AS1, prefix = PREFIX1, maxPrefixLength = None)
  val RTR_PREFIX2 = RtrPrefix(asn = AS1, prefix = PREFIX2, maxPrefixLength = None)

  val VALIDATED_ANNOUNCEMENT1 = BgpValidatedAnnouncement(route = ANNOUNCED_ROUTE1, validates = Seq[RtrPrefix](RTR_PREFIX1), invalidates = Seq.empty[RtrPrefix]) //route: AnnouncedRoute, validates: Seq[RtrPrefix], invalidates: Seq[RtrPrefix])
  val VALIDATED_ANNOUNCEMENT2 = BgpValidatedAnnouncement(route = ANNOUNCED_ROUTE2, validates = Seq.empty[RtrPrefix], invalidates = Seq[RtrPrefix](RTR_PREFIX2)) //route: AnnouncedRoute, validates: Seq[RtrPrefix], invalidates: Seq[RtrPrefix])
  val VALIDATED_ANNOUNCEMENT3 = BgpValidatedAnnouncement(route = ANNOUNCED_ROUTE3, validates = Seq.empty[RtrPrefix], invalidates = Seq.empty[RtrPrefix]) //route: AnnouncedRoute, validates: Seq[RtrPrefix], invalidates: Seq[RtrPrefix])

  val TEST_BGP_DUMPS = {
    Seq(BgpRisDump("http://localhost/", None, Seq(
        new BgpRisEntry(origin = AS1, prefix = PREFIX1, visibility = 10),
        new BgpRisEntry(origin = AS2, prefix = PREFIX2, visibility = 5),
        new BgpRisEntry(origin = AS2, prefix = PREFIX3, visibility = 4),
        new BgpRisEntry(origin = AS3, prefix = PREFIX4, visibility = 5))))
  }

  val TEST_ANNOUNCEMENTS_FROM_RIS: IndexedSeq[BgpAnnouncement] = Vector(ANNOUNCED_ROUTE1, ANNOUNCED_ROUTE2, ANNOUNCED_ROUTE3)

  val TEST_RTR_PREFIXES = Vector(RTR_PREFIX1, RTR_PREFIX2)

  val TEST_VALIDATED_ANNOUNCEMENTS = {
    Set.empty[BgpValidatedAnnouncement] +
      VALIDATED_ANNOUNCEMENT1 +
      VALIDATED_ANNOUNCEMENT2 +
      VALIDATED_ANNOUNCEMENT3
  }

  implicit val actorSystem = akka.actor.ActorSystem()
  private val subject = new BgpAnnouncementValidator

//  test("should update announced routes with visibility threshold 5") {
//    val announcementValidator = new BgpAnnouncementValidator {
//      override protected def retrieveBgpRisDumps(dumps: Promise[Seq[BgpRisDump]]) = Promise { TEST_BGP_DUMPS }
//    }
//
//    announcementValidator.updateBgpRisDumps()
//    val announcementsFound = announcementValidator.announcedRoutes.get
//
//    announcementsFound.size should equal(TEST_ANNOUNCEMENTS_FROM_RIS.size)
//
//    announcementsFound.foreach {
//      announcement => TEST_ANNOUNCEMENTS_FROM_RIS should contain(announcement)
//    }
//  }
//
  test("should validate prefixes") {
    subject.startUpdate(TEST_ANNOUNCEMENTS_FROM_RIS, TEST_RTR_PREFIXES)

    val result = subject.validatedAnnouncements
    result.size should equal(TEST_VALIDATED_ANNOUNCEMENTS.size)
    TEST_VALIDATED_ANNOUNCEMENTS.foreach {
      expectedAnnouncement => result should contain(expectedAnnouncement)
    }
  }

}
