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
package controllers

import java.net.URI

import net.ripe.rpki.commons.validation.{ValidationCheck, ValidationStatus, ValidationString}
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.support.ControllerTestCase
import net.ripe.rpki.validator.testing.TestingObjectMother
import net.ripe.rpki.validator.util.TrustAnchorLocator
import net.ripe.rpki.validator.views.FetchResultsTableData
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class TrustAnchorsControllerTest extends ControllerTestCase {
  private val ta = TestingObjectMother.TA
  private val message = "some message"
  private val uri: URI = URI.create("rsync://some.host/obj.o")
  private val invalidObject: InvalidObject = InvalidObject(
    "obj",
    uri,
    None,
    Set(new ValidationCheck(ValidationStatus.FETCH_ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_FOUND, uri.toString, message))
  )
  private val invalidObjects = Seq(invalidObject)

  override def controller = new ControllerFilter with TrustAnchorsController {
    override def trustAnchors = new TrustAnchors(Seq(ta))
    override def validatedObjects = new ValidatedObjects(Map((ta.locator, TrustAnchorValidations(invalidObjects))))
    override protected def startTrustAnchorValidation(trustAnchors: Seq[String]) = sys.error("TODO")
    override protected def updateTrustAnchorState(locator: TrustAnchorLocator, enabled: Boolean) {}
  }

  test("list trust anchors") {
    get("/trust-anchors") {
      response.status should equal(200)
      result.isInstanceOf[views.TrustAnchorsView] should be(true)
    }
  }

  test("list all fetch errors") {
    get(s"/trust-anchor-monitor/fetch-detail/${ta.identifierHash}?$extraParamsYouDontNeedToKnowAbout") {
      response.status should equal(200)
      val records = result.asInstanceOf[FetchResultsTableData].getAllRecords()
      records.size should be(1)
      records.head.subjectChain should be(invalidObject.subjectChain)
      records.head.messages should include(uri.toString)
      records.head.messages should include(message)
    }
  }

  //used by DataTableJsonView
  val extraParamsYouDontNeedToKnowAbout = "sSearch=&iDisplayStart=0&iDisplayLength=10&iSortCol_0=0&sSortDir_0=asc"

}
