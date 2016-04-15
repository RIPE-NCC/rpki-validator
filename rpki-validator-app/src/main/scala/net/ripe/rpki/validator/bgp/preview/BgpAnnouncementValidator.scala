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

import lib.NumberResources._
import net.ripe.rpki.validator.models.{RouteValidity, RtrPrefix}
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import grizzled.slf4j.Logging
import net.ripe.rpki.validator.lib.DateAndTime
import net.ripe.rpki.validator.models.RouteValidity._

import scala.concurrent.stm.{MaybeTxn, Ref}

case class BgpAnnouncement(asn: Asn, prefix: IpRange) {
  def interval = NumberResourceInterval(prefix.getStart, prefix.getEnd)
}

case class BgpValidatedAnnouncement(announced: BgpAnnouncement, valids: Seq[RtrPrefix] = Seq.empty,
                                    invalidsAsn: Seq[RtrPrefix] = Seq.empty,
                                    invalidsLength: Seq[RtrPrefix] = Seq.empty) {
  require(!invalidsAsn.exists(_.asn == announced.asn), "invalidsAsn must not contain the announced ASN")
  require(!invalidsLength.exists(_.asn != announced.asn), "invalidsLength must only contain VRPs that refer to the same ASN")

  def asn = announced.asn
  def prefix = announced.prefix
  def validity = {
    if (valids.nonEmpty) RouteValidity.Valid
    else if (invalidsLength.nonEmpty) RouteValidity.InvalidLength
    else if (invalidsAsn.nonEmpty) RouteValidity.InvalidAsn
    else RouteValidity.Unknown
  }
}

object BgpAnnouncementValidator {
  val VISIBILITY_THRESHOLD = 5

  def validate(announcement: BgpAnnouncement, prefixes: Seq[RtrPrefix]): BgpValidatedAnnouncement =
    validate(announcement, NumberResourceIntervalTree(prefixes: _*))

  def validate(announcement: BgpAnnouncement, prefixTree: NumberResourceIntervalTree[RtrPrefix]): BgpValidatedAnnouncement = {
    val matchingPrefixes = prefixTree.findExactAndAllLessSpecific(announcement.interval)
    val groupedByValidity = matchingPrefixes.groupBy {
      case prefix if hasInvalidAsn(prefix, announcement) => InvalidAsn
      case prefix if hasInvalidPrefixLength(prefix, announcement) => InvalidLength
      case _ => Valid
    }
    BgpValidatedAnnouncement(announcement,
      groupedByValidity.getOrElse(Valid, Seq.empty),
      groupedByValidity.getOrElse(InvalidAsn, Seq.empty),
      groupedByValidity.getOrElse(InvalidLength, Seq.empty))
  }

  private def hasInvalidAsn(prefix: RtrPrefix, announced: BgpAnnouncement) =
    prefix.asn != announced.asn

  private def hasInvalidPrefixLength(prefix: RtrPrefix, announced: BgpAnnouncement) =
    prefix.maxPrefixLength.getOrElse(prefix.prefix.getPrefixLength) < announced.prefix.getPrefixLength
}

class BgpAnnouncementValidator(implicit actorSystem: akka.actor.ActorSystem) extends Logging {
  import scala.concurrent.stm._

  private val _validatedAnnouncements = Ref(IndexedSeq.empty[BgpValidatedAnnouncement])

  def validatedAnnouncements: IndexedSeq[BgpValidatedAnnouncement] = _validatedAnnouncements.single.get

  def startUpdate(announcements: Seq[BgpAnnouncement], prefixes: Seq[RtrPrefix]) = {
    val v = validate(announcements, prefixes)
    _validatedAnnouncements.single.set(v)
  }

  private def validate(announcements: Seq[BgpAnnouncement], prefixes: Seq[RtrPrefix]): IndexedSeq[BgpValidatedAnnouncement] = {

    info("Started validating " + announcements.size + " BGP announcements with " + prefixes.size + " RTR prefixes.")
    val prefixTree = NumberResourceIntervalTree(prefixes: _*)
    val (result, time) = DateAndTime.timed {
      announcements.par.map(BgpAnnouncementValidator.validate(_, prefixTree)).seq.toIndexedSeq
    }
    info(s"Completed validating ${result.size} BGP announcements with ${prefixes.size} RTR prefixes in ${time/1000.0} seconds")
    result
  }
}
