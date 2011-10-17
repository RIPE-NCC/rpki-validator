/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package rtr

import java.io.File
import java.net.URI

import scala.collection.JavaConverters._
import scala.collection.mutable.HashMap
import scala.util.Random

import org.joda.time.DateTime
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.BeforeAndAfter
import org.scalatest.BeforeAndAfterAll
import org.scalatest.FunSuite

import models._
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.commons.certification.cms.roa.RoaCms
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother
import net.ripe.commons.certification.cms.roa.RoaPrefix
import net.ripe.commons.certification.ValidityPeriod
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import net.ripe.rpki.validator.config.Atomic
import net.ripe.rpki.validator.config.Database
import net.ripe.rpki.validator.models.ValidatedRoa

@RunWith(classOf[JUnitRunner])
class RtrServerTest extends FunSuite with BeforeAndAfterAll with BeforeAndAfter with ShouldMatchers {

  var cache: Atomic[Database] = null

  var nonce: Short = new Random().nextInt(65536).toShort

  var handler: RTRServerHandler = null

  override def beforeAll() = {
    var trustAnchors: TrustAnchors = new TrustAnchors(collection.mutable.Seq.empty[TrustAnchor])
    var validatedRoas: Roas = new Roas(new HashMap[String, Option[Seq[ValidatedRoa]]])
    cache = new Atomic(Database(Whitelist(), trustAnchors, validatedRoas))

    handler = new RTRServerHandler(
      getCurrentCacheSerial = { () => cache.get.version },
      getCurrentRoas = { () => cache.get.roas },
      getCurrentNonce = { () => nonce })
  }

  test("Should find distinct ROA prefixes") {

    val tal = getTalForTesting()

    // TODO: use the method that allows explicit list of roa prefixes for testing

    val ASN1 = Asn.parse("AS65000")
    val ASN2 = Asn.parse("AS65001")

    val ROA_PREFIX_V4_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), 24)
    val ROA_PREFIX_V4_2 = new RoaPrefix(IpRange.parse("10.32.0.0/12"), null)
    val ROA_PREFIX_V6_1 = new RoaPrefix(IpRange.parse("2001:0:200::/39"), null)

    val prefixes1 = List[RoaPrefix](
      ROA_PREFIX_V4_1,
      ROA_PREFIX_V6_1,
      ROA_PREFIX_V6_1) // Duplicate prefix on same ROA should be filtered

    val prefixes2 = List[RoaPrefix](
      ROA_PREFIX_V4_1, // Duplicate prefix on other ROA for SAME ASN should be filtered
      ROA_PREFIX_V4_2) // but this should be added

    val prefixes3 = List[RoaPrefix](
      ROA_PREFIX_V4_1) // This ROA has another ASN so this combo should be found

    val validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1))

    val roa1: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes1.asJava, validityPeriod, ASN1)
    val roa1Uri: URI = URI.create("rsync://example.com/roa1.roa")
    val validatedRoa1: ValidatedRoa = new ValidatedRoa(roa1, roa1Uri, tal)

    val roa2: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes2.asJava, validityPeriod, ASN1)
    val roa2Uri: URI = URI.create("rsync://example.com/roa2.roa")
    val validatedRoa2: ValidatedRoa = new ValidatedRoa(roa2, roa2Uri, tal)

    val roa3: RoaCms = RoaCmsObjectMother.getRoaCms(prefixes3.asJava, validityPeriod, ASN2)
    val roa3Uri: URI = URI.create("rsync://example.com/roa3.roa")
    val validatedRoa3: ValidatedRoa = new ValidatedRoa(roa3, roa2Uri, tal)

    val roas = collection.mutable.Seq.apply[ValidatedRoa](validatedRoa1, validatedRoa2, validatedRoa3)

    cache.update { db =>
      db.copy(roas = db.roas.update(tal, roas), version = db.version + 1)
    }

    val distinctRoaPrefixes = handler.getDistinctRoaPrefixes()

    distinctRoaPrefixes.size should equal(4)
    distinctRoaPrefixes.contains((ROA_PREFIX_V4_1, ASN1)) should be (true)
    distinctRoaPrefixes.contains((ROA_PREFIX_V4_2, ASN1)) should be (true)
    distinctRoaPrefixes.contains((ROA_PREFIX_V6_1, ASN1)) should be (true)
    distinctRoaPrefixes.contains((ROA_PREFIX_V4_1, ASN2)) should be (true)

  }

  def getTalForTesting() = {
    val file: File = new File("/tmp")
    val caName = "test ca"
    val location: URI = URI.create("rsync://example.com/")
    val publicKeyInfo = "info"
    val prefetchUris: java.util.List[URI] = new java.util.ArrayList[URI]()

    new TrustAnchorLocator(file, caName, location, publicKeyInfo, prefetchUris)
  }
}
