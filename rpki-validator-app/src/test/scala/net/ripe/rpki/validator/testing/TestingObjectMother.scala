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
package testing

import java.io.File
import java.net.URI
import java.util
import java.util.Collections

import net.ripe.ipresource.{Asn, IpRange}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.roa.{RoaCms, RoaCmsObjectMother, RoaPrefix}
import net.ripe.rpki.commons.validation.ValidationCheck
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.DateTime

object TestingObjectMother {

  val ASN1 = new Asn(65000)
  val ASN2 = new Asn(65001)
  val ASN3 = new Asn(65003)

  val ROA_PREFIX_V4_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), 24)
  val ROA_PREFIX_V4_2 = new RoaPrefix(IpRange.parse("10.32.0.0/12"), null)
  val ROA_PREFIX_V6_1 = new RoaPrefix(IpRange.parse("2001:0:200::/39"), null)
  val WHITELIST_PREFIX_1: IpRange = IpRange.parse("10.0.0.0/8")
  val UNUSED_PREFIX_FOR_FILTER = IpRange.parse("192.168.1.0/24")

  val TAL = {
    val file: File = new File("/tmp")
    val caName = "test ca"
    val location: URI = URI.create("rsync://example.com/")
    val publicKeyInfo = "info"
    val prefetchUris = Collections.emptyList[URI]()

    new TrustAnchorLocator(file, caName, Collections.singletonList(location), publicKeyInfo, prefetchUris)
  }

  val TA = TrustAnchor(locator = TAL, status = Idle(nextUpdate = new DateTime()))

  val ASN1_TO_ROA_PREFIX_V4_1: RtrPrefix = RtrPrefix(ASN1, ROA_PREFIX_V4_1.getPrefix, Some(ROA_PREFIX_V4_1.getMaximumLength), Some(TAL))
  val ASN1_TO_ROA_PREFIX_V4_2: RtrPrefix = RtrPrefix(ASN1, ROA_PREFIX_V4_2.getPrefix, None, Some(TAL))
  val ASN1_TO_ROA_PREFIX_V6_1: RtrPrefix = RtrPrefix(ASN1, ROA_PREFIX_V6_1.getPrefix, None, Some(TAL))
  val ASN2_TO_ROA_PREFIX_V4_1: RtrPrefix = RtrPrefix(ASN2, ROA_PREFIX_V4_1.getPrefix, Some(ROA_PREFIX_V4_1.getMaximumLength), Some(TAL))
  val ASN3_TO_WHITELIST1: RtrPrefix = RtrPrefix(ASN3, WHITELIST_PREFIX_1, None, Some(TAL))

  def ROAS = {
    val prefixes1 = util.Arrays.asList(
      ROA_PREFIX_V4_1,
      ROA_PREFIX_V6_1,
      ROA_PREFIX_V6_1) // Duplicate prefix on same ROA should be filtered

    val prefixes2 = Collections.singletonList(
      ROA_PREFIX_V4_1) // This ROA has another ASN so this combo should be found

    val prefixes3 = util.Arrays.asList(
      ROA_PREFIX_V4_1, // Duplicate prefix on other ROA for SAME ASN should be filtered
      ROA_PREFIX_V4_2) // but this should be added

    val validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1))

    val roa1: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes1, validityPeriod, ASN1)
    val roa1Uri: URI = URI.create("rsync://example.com/roa1.roa")
    val validatedRoa1 = ValidObject("roa1", roa1Uri, Some(Array[Byte](1)), Set.empty[ValidationCheck], roa1)

    val roa2: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes2, validityPeriod, ASN2)
    val roa2Uri: URI = URI.create("rsync://example.com/roa2.roa")
    val validatedRoa2 = ValidObject("roa2", roa2Uri, Some(Array[Byte](2)), Set.empty[ValidationCheck], roa2)

    val roa3: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes3, validityPeriod, ASN1)
    val roa3Uri: URI = URI.create("rsync://example.com/roa3.roa")
    val validatedRoa3 = ValidObject("roa3", roa3Uri, Some(Array[Byte](3)), Set.empty[ValidationCheck], roa3)

    val roas = Seq(validatedRoa1, validatedRoa2, validatedRoa3)
    new ValidatedObjects(Map(TAL -> TrustAnchorValidations(roas)))
  }


  def FILTERS = Filters(Set(IgnoreFilter(ROA_PREFIX_V6_1.getPrefix)))

  def WHITELIST = Whitelist(Set(ASN3_TO_WHITELIST1))
}
