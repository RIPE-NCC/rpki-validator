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

import net.ripe.rpki.commons.validation.roa.RouteValidityState
import lib.NumberResources._
import models.RtrPrefix
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import grizzled.slf4j.Logging

case class BgpAnnouncement private (asn: Asn, interval: NumberResourceInterval) {
  def prefix = interval.start.upTo(interval.end).asInstanceOf[IpRange]
}
object BgpAnnouncement {
  def apply(asn: Asn, prefix: IpRange) = new BgpAnnouncement(asn, NumberResourceInterval(prefix.getStart, prefix.getEnd))
}
case class BgpValidatedAnnouncement(route: BgpAnnouncement, validates: Seq[RtrPrefix], invalidates: Seq[RtrPrefix]) {
  def asn = route.asn
  def prefix = route.prefix
  def validity = {
    if (validates.nonEmpty) RouteValidityState.VALID
    else if (invalidates.nonEmpty) RouteValidityState.INVALID
    else RouteValidityState.UNKNOWN
  }
}

object BgpAnnouncementValidator {
  val VISIBILITY_THRESHOLD = 5
}
class BgpAnnouncementValidator(implicit actorSystem: akka.actor.ActorSystem) extends Logging {
  import actorSystem.dispatcher
  import scala.concurrent.duration._

  private val _validatedAnnouncements = akka.agent.Agent(IndexedSeq.empty[BgpValidatedAnnouncement])

  def validatedAnnouncements: IndexedSeq[BgpValidatedAnnouncement] = _validatedAnnouncements.await(30.seconds)

  def startUpdate(announcements: Seq[BgpAnnouncement], prefixes: Seq[RtrPrefix]): Unit = _validatedAnnouncements.sendOff {
    _ => validate(announcements, prefixes)
  }

  private def validate(announcements: Seq[BgpAnnouncement], prefixes: Seq[RtrPrefix]): IndexedSeq[BgpValidatedAnnouncement] = {
    info("Started validating " + announcements.size + " BGP announcements with " + prefixes.size + " RTR prefixes.")
    val prefixTree = NumberResourceIntervalTree(prefixes: _*)

    val result = announcements.par.map({ route =>
      val matchingPrefixes = prefixTree.findExactAndAllLessSpecific(route.interval)
      val (validates, invalidates) = matchingPrefixes.partition(validatesAnnouncedRoute(_, route))
      BgpValidatedAnnouncement(route, validates, invalidates)
    }).seq.toIndexedSeq

    info("Completed validating " + result.size + " BGP announcements with " + prefixes.size + " RTR prefixes.")

    result
  }

  private def validatesAnnouncedRoute(prefix: RtrPrefix, announced: BgpAnnouncement): Boolean = {
    prefix.asn == announced.asn &&
      prefix.maxPrefixLength.getOrElse(prefix.prefix.getPrefixLength) >= announced.prefix.getPrefixLength
  }

}
