package net.ripe.rpki.validator
package models

import scalaz._
import Scalaz._

import net.ripe.ipresource.{IpRange, Asn}
import lib.Validation._


case class RtrPrefix (val asn: Asn, val prefix: IpRange, val maxPrefixLength: Option[Int])

object RtrPrefix {
  def validate(asn: Asn, prefix: IpRange, maxPrefixLength: Option[Int]): ValidationNEL[ErrorMessage, RtrPrefix] = {
    if (!prefix.isLegalPrefix()) {
      ErrorMessage("must be a legal IPv4 or IPv6 prefix", Some("prefix")).failNel
    } else {
      val allowedPrefixLengthRange = prefix.getPrefixLength() to prefix.getType().getBitSize()
      val validated = optional(containedIn(allowedPrefixLengthRange)).apply(maxPrefixLength) map { _ =>
        new RtrPrefix(asn, prefix, maxPrefixLength)
      }
      liftFailErrorMessage(validated, Some("maxPrefixLength"))
    }
  }
}

