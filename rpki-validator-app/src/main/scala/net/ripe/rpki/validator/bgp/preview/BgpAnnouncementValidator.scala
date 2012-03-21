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
import scala.concurrent.SyncVar
import scala.concurrent.ops._
import scalaz.Reducer
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
  var announcedRoutes = Promise(IndexedSeq.empty[AnnouncedRoute])

  @volatile
  var validatedAnnouncements = Promise(IndexedSeq.empty[ValidatedAnnouncement])

  private val latestRtrPrefixes = new SyncVar[Set[RtrPrefix]]

  def updateAnnouncedRoutes(): Unit = {
    info("Started retrieving new RIS dump files")

    val oldRoutes = announcedRoutes.get

    announcedRoutes = Promise {
      try {
        val result = readBgpEntries
          .filter(_.visibility >= VISIBILITY_THRESHOLD)
          .map(entry => AnnouncedRoute(entry.origin, entry.prefix))
          .toArray.distinct
        info("Finished retrieving new RIS dump files, found " + result.size + " announcements")
        result
      } catch {
        case e: Exception => {
          error("An error occured while trying to read new RIS bgp entries, using old values")
          oldRoutes
        }
      }
    }

  }

  protected def readBgpEntries() = {
    RisWhoisParser.parseFromUrl(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz")) ++
      RisWhoisParser.parseFromUrl(new java.net.URL("http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"))
  }

  def updateRtrPrefixes(newRtrPrefixes: Set[RtrPrefix]): Unit = {
    validatedAnnouncements = Promise({
      val routes = announcedRoutes.get

      info("Started validating " + routes.size + " BGP announcements with " + newRtrPrefixes.size + " RTR prefixes.")
      val prefixTree = NumberResourceIntervalTree(newRtrPrefixes.toSeq: _*)

      routes.par.map(
        route => {
          val matchingPrefixes = prefixTree.filterContaining(route.interval)
          val (validates, invalidates) = matchingPrefixes.partition(validatesAnnouncedRoute(_, route))
          ValidatedAnnouncement(route, validates, invalidates)
        }).seq.toIndexedSeq
    })

    info("Completed validating " + validatedAnnouncements.get.size + " BGP announcements with " + newRtrPrefixes.size + " RTR prefixes.")
  }

  private def validatesAnnouncedRoute(prefix: RtrPrefix, announced: AnnouncedRoute): Boolean = {
    prefix.asn == announced.asn &&
      prefix.maxPrefixLength.getOrElse(prefix.prefix.getPrefixLength()) >= announced.prefix.getPrefixLength()
  }
}

object BgpAnnouncementValidator {

  private val singletonValidator = new BgpAnnouncementValidator

  def updateAnnouncedRoutes() = singletonValidator.updateAnnouncedRoutes()
  def updateRtrPrefixes(newRtrPrefixes: Set[RtrPrefix]) = singletonValidator.updateRtrPrefixes(newRtrPrefixes)
  def getValidatedAnnouncements = singletonValidator.validatedAnnouncements.get

}
