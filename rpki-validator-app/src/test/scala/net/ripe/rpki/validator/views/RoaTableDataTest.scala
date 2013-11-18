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
package views

import testing.TestingObjectMother._
import models.RtrPrefix
import lib.Java
import net.ripe.rpki.validator.support.ValidatorTestCase

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RoaTableDataTest extends ValidatorTestCase {

  val ROA_TABLE_RECORD_1 = RtrPrefix(ASN1, ROA_PREFIX_V4_1.getPrefix(), Java.toOption(ROA_PREFIX_V4_1.getMaximumLength), Option(TAL))
  val ROA_TABLE_RECORD_2 = RtrPrefix(ASN1, ROA_PREFIX_V4_2.getPrefix(), Java.toOption(ROA_PREFIX_V4_2.getMaximumLength), Option(TAL))
  val ROA_TABLE_RECORD_3 = RtrPrefix(ASN1, ROA_PREFIX_V6_1.getPrefix(), Java.toOption(ROA_PREFIX_V6_1.getMaximumLength), Option(TAL))
  val ROA_TABLE_RECORD_4 = RtrPrefix(ASN2, ROA_PREFIX_V4_1.getPrefix(), Java.toOption(ROA_PREFIX_V4_1.getMaximumLength), Option(TAL))

  val subject = new RoaTableData(ROAS) {
    override def getParam(name: String) = "1"
  }

  test("should get roas") {
    val records = subject.getAllRecords()
    records should have length 6 // NOTE: There are duplicates
    records should contain(ROA_TABLE_RECORD_1)
    records should contain(ROA_TABLE_RECORD_2)
    records should contain(ROA_TABLE_RECORD_3)
    records should contain(ROA_TABLE_RECORD_4)
  }

  test("should filter by string") {
    val filtered = subject.filterRecords(subject.getAllRecords().distinct, "10")
    filtered should have length 3
    filtered should contain(ROA_TABLE_RECORD_1)
    filtered should contain(ROA_TABLE_RECORD_2)
    filtered should contain(ROA_TABLE_RECORD_4)
  }

  test("should filter by ASN") {
    val filtered = subject.filterRecords(subject.getAllRecords().distinct, ASN2)
    filtered should have length 1
    filtered should contain(ROA_TABLE_RECORD_4)
  }

  test("should filter by IP Range") {
    val filtered = subject.filterRecords(subject.getAllRecords().distinct, ROA_PREFIX_V4_2.getPrefix())
    filtered should have length 1
    filtered should contain(ROA_TABLE_RECORD_2)
  }

  test("should sort by AS") {
    val sorted = subject.sortRecords(subject.getAllRecords().distinct, 0)
    sorted should have length 4
    sorted(0).asn should equal (ASN1)
    sorted(1).asn should equal (ASN1)
    sorted(2).asn should equal (ASN1)
    sorted(3).asn should equal (ASN2)
  }

  test("should sort by Prefix") {
    val sorted = subject.sortRecords(subject.getAllRecords().distinct, 1)
    sorted should have length 4
    sorted(0).prefix should equal (ROA_PREFIX_V4_2.getPrefix())
    sorted(1).prefix should equal (ROA_PREFIX_V4_1.getPrefix())
    sorted(2).prefix should equal (ROA_PREFIX_V4_1.getPrefix())
    sorted(3).prefix should equal (ROA_PREFIX_V6_1.getPrefix())
  }

  test("should sort by effective max length") {
    val sorted = subject.sortRecords(subject.getAllRecords().distinct, 2)
    sorted should have length 4
    sorted(0).effectiveMaxPrefixLength should equal (ROA_PREFIX_V4_2.getEffectiveMaximumLength())
    sorted(1).effectiveMaxPrefixLength should equal (ROA_PREFIX_V4_1.getEffectiveMaximumLength())
    sorted(2).effectiveMaxPrefixLength should equal (ROA_PREFIX_V4_1.getEffectiveMaximumLength())
    sorted(3).effectiveMaxPrefixLength should equal (ROA_PREFIX_V6_1.getEffectiveMaximumLength())
  }


}
