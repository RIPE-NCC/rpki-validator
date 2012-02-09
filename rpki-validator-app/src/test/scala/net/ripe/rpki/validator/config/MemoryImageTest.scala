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
package net.ripe.rpki.validator.config

import org.scalatest.{BeforeAndAfter, BeforeAndAfterAll, FunSuite}
import org.scalatest.matchers.ShouldMatchers
import scala.Predef._
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.testing.TestingObjectMother._
import net.ripe.rpki.validator.lib.UserPreferences

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class MemoryImageTest extends FunSuite with BeforeAndAfterAll with BeforeAndAfter with ShouldMatchers {

  var subject: MemoryImage = null
  var trustAnchors: TrustAnchors = null

  override def beforeAll() = {
    trustAnchors = new TrustAnchors(collection.mutable.Seq.empty[TrustAnchor])
  }

  test("Should find distinct ROA prefixes") {

    subject = new MemoryImage(Filters(), Whitelist(), trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(4)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_2)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V6_1)
    distinctRoaPrefixes should contain (ASN2_TO_ROA_PREFIX_V4_1)
  }

  test("Should list whitelist entries when no roas") {
    subject = new MemoryImage(Filters(), WHITELIST, trustAnchors, ValidatedObjects(trustAnchors), UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(1)
    distinctRoaPrefixes should contain (ASN3_TO_WHITELIST1)
  }

  test("Should mix whitelist entries with roas for same prefix") {
    val whitelist = WHITELIST.addEntry(ASN1_TO_ROA_PREFIX_V4_2)

    subject = new MemoryImage(Filters(), whitelist, trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(5)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_2)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V6_1)
    distinctRoaPrefixes should contain (ASN2_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN3_TO_WHITELIST1)
  }

  test("Should mix whitelist entries with roas for same prefix and a filter") {
    val whitelist = WHITELIST.addEntry(ASN1_TO_ROA_PREFIX_V4_2)

    subject = new MemoryImage(FILTERS, whitelist, trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(4)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_2)
    distinctRoaPrefixes should contain (ASN2_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN3_TO_WHITELIST1)
  }

  test("Should mix whitelist entries with roas for same prefix and more than one filter") {
    val whitelist = WHITELIST.addEntry(ASN1_TO_ROA_PREFIX_V4_2)

    val filters: Filters = FILTERS.addFilter(new IgnoreFilter(UNUSED_PREFIX_FOR_FILTER))

    subject = new MemoryImage(filters, whitelist, trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(4)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_2)
    distinctRoaPrefixes should contain (ASN2_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN3_TO_WHITELIST1)
  }

  test("Should prevail whitelist entry over roa prefix filtered out by filter") {
    val whitelist = WHITELIST.addEntry(ASN1_TO_ROA_PREFIX_V6_1)

    subject = new MemoryImage(FILTERS, whitelist, trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val distinctRoaPrefixes = subject.getDistinctRtrPrefixes()

    distinctRoaPrefixes.size should equal(5)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V4_2)
    distinctRoaPrefixes should contain (ASN1_TO_ROA_PREFIX_V6_1)
    distinctRoaPrefixes should contain (ASN2_TO_ROA_PREFIX_V4_1)
    distinctRoaPrefixes should contain (ASN3_TO_WHITELIST1)
  }
  
  test("should not increase version when updating software update preferences") {
    subject = new MemoryImage(FILTERS, WHITELIST, trustAnchors, ROAS, UserPreferences(updateAlertActive = false))
    val currentVersion = subject.version

    subject.updateUserPreferences(UserPreferences(true))
    subject.version should equal (currentVersion)
  }
}
