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
package models

import scalaz._
import Scalaz._
import net.ripe.ipresource.{ IpRange, Asn }
import lib.Validation._
import lib.NumberResources._
import net.ripe.rpki.validator.util.TrustAnchorLocator

case class RtrPrefix(asn: Asn, prefix: IpRange, maxPrefixLength: Option[Int] = None, trustAnchorLocator: Option[TrustAnchorLocator] = None) {
  def interval = NumberResourceInterval(prefix.getStart, prefix.getEnd)
  def effectiveMaxPrefixLength = maxPrefixLength.getOrElse(prefix.getPrefixLength)
  def getCaName = trustAnchorLocator.map(_.getCaName).getOrElse("unknown")
}

object RtrPrefix {
  def validate(asn: Asn, prefix: IpRange, maxPrefixLength: Option[Int]): ValidationNEL[FeedbackMessage, RtrPrefix] = {
    if (!prefix.isLegalPrefix) {
      ErrorMessage("must be a legal IPv4 or IPv6 prefix", Some("prefix")).failNel
    } else {
      val allowedPrefixLengthRange = prefix.getPrefixLength to prefix.getType.getBitSize
      val validated = optional(containedIn(allowedPrefixLengthRange)).apply(maxPrefixLength) map { _ =>
        new RtrPrefix(asn, prefix, maxPrefixLength)
      }
      liftFailErrorMessage(validated, Some("maxPrefixLength"))
    }
  }

  /**
   * Takes an RtrPrefix and returns the associated IP range.
   */
  implicit object RtrPrefixReducer extends Reducer[RtrPrefix, NumberResourceInterval] {
    override def unit(prefix: RtrPrefix) = prefix.interval
  }

}

