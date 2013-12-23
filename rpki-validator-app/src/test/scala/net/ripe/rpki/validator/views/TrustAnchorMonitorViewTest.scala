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

import net.ripe.rpki.validator.support.ValidatorTestCase
import net.ripe.rpki.validator.models._

import org.scalatest.mock.MockitoSugar


import net.ripe.rpki.validator.testing.TestingObjectMother


@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrustAnchorMonitorViewTest extends ValidatorTestCase with MockitoSugar {

  import models.ValidatedObjectsTest._
  import TestingObjectMother._

  test("Should not raise alert for invalid object fraction when validated object count == 0") {
    val taValidations = TrustAnchorValidations()

    val subject = new TrustAnchorMonitorView(ta = TA, trustAnchorValidations  = taValidations)

    subject.hasTooHighErrorFraction should be (false)
  }

  test("Should not raise alert for invalid object fraction when less then 10% errors") {
    val validatedObjects = makeListOfValidObjects(10) ++ makeListOfInvalidObjects(1)
    val taValidations = TrustAnchorValidations(validatedObjects)

    val subject = new TrustAnchorMonitorView(ta = TA, trustAnchorValidations  = taValidations)

    subject.hasTooHighErrorFraction should be (false)
  }

  test("Should raise alert for invalid object fraction when 10% or more errors") {
    val validatedObjects = makeListOfValidObjects(9) ++ makeListOfInvalidObjects(1)

    val taValidations = TrustAnchorValidations(validatedObjects)

    val subject = new TrustAnchorMonitorView(ta = TA, trustAnchorValidations  = taValidations)

    subject.hasTooHighErrorFraction should be (true)
  }

  test("Should raise alert when object drop seen") {

    val initialValidatedObjects = ValidatedObjects(new TrustAnchors(Seq(TA)))
    val validatedObjectsAfterFirstRun = initialValidatedObjects.update(TAL, makeListOfValidObjects(10))
    val validatedObjectsAfterSecondRun = validatedObjectsAfterFirstRun.update(TAL, makeListOfValidObjects(8) ++ makeListOfInvalidObjects(1))

    val subject = new TrustAnchorMonitorView(ta = TA, trustAnchorValidations = validatedObjectsAfterSecondRun.all.get(TAL).get)

    subject.hasUnexpectedDrop should be (true)
  }


}
