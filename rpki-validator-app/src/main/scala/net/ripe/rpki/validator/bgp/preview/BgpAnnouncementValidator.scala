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

import scala.collection.JavaConverters._
import scalaz._, Scalaz._
import scalaz.concurrent.Promise
import net.ripe.commons.certification.validation.roa.RouteValidityState
import lib.Process._
import lib.NumberResources._
import models.RtrPrefix
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import grizzled.slf4j.Logging

case class AnnouncedRoute private (asn: Asn, interval: NumberResourceInterval) {
  def prefix = interval.start.upTo(interval.end).asInstanceOf[IpRange]
}
object AnnouncedRoute {
  def apply(asn: Asn, prefix: IpRange) = new AnnouncedRoute(asn, NumberResourceInterval(prefix.getStart, prefix.getEnd))
}
case class ValidatedAnnouncement(route: AnnouncedRoute, validates: Seq[RtrPrefix], invalidates: Seq[RtrPrefix]) {
  def asn = route.asn
  def prefix = route.prefix
  def validity = {
    if (validates.nonEmpty) RouteValidityState.VALID
    else if (invalidates.nonEmpty) RouteValidityState.INVALID
    else RouteValidityState.UNKNOWN
  }
}

class BgpAnnouncementValidator extends Logging {

  val VISIBILITY_THRESHOLD = 5

  @volatile
  private var _bgpRisDumps = Promise {
    Seq(
      BgpRisDump(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz")),
      BgpRisDump(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz")))
  }

  @volatile
  private var _validatedAnnouncements = Promise(IndexedSeq.empty[ValidatedAnnouncement])

  def validatedAnnouncements = _validatedAnnouncements.get

  def updateBgpRisDumps(): Unit = {
    _bgpRisDumps = retrieveBgpRisDumps(_bgpRisDumps)
  }

  def updateRtrPrefixes(newRtrPrefixes: Set[RtrPrefix]): Unit = {
    _validatedAnnouncements = announcedRoutes map { routes =>
      info("Started validating " + routes.size + " BGP announcements with " + newRtrPrefixes.size + " RTR prefixes.")
      val prefixTree = NumberResourceIntervalTree(newRtrPrefixes.toSeq: _*)

      val result = routes.par.map({ route =>
          val matchingPrefixes = prefixTree.filterContaining(route.interval)
          val (validates, invalidates) = matchingPrefixes.partition(validatesAnnouncedRoute(_, route))
          ValidatedAnnouncement(route, validates, invalidates)
        }).seq.toIndexedSeq

      info("Completed validating " + result.size + " BGP announcements with " + newRtrPrefixes.size + " RTR prefixes.")
      result
    }
  }

  protected def retrieveBgpRisDumps(dumps: Promise[Seq[BgpRisDump]]) = dumps flatMap { _.map(BgpRisDump.refresh).sequence }

  private def validatesAnnouncedRoute(prefix: RtrPrefix, announced: AnnouncedRoute): Boolean = {
    prefix.asn == announced.asn &&
      prefix.maxPrefixLength.getOrElse(prefix.prefix.getPrefixLength()) >= announced.prefix.getPrefixLength()
  }

  private[preview] def announcedRoutes = _bgpRisDumps map { dumps =>
    val routes = for {
      dump <- dumps
      entry <- dump.entries
      if entry.visibility >= VISIBILITY_THRESHOLD
    } yield {
      AnnouncedRoute(entry.origin, entry.prefix)
    }
    routes.distinct
  }

}

object BgpAnnouncementValidator extends BgpAnnouncementValidator
