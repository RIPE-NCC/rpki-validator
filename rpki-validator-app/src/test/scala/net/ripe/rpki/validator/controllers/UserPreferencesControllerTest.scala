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

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner

import support.ControllerTestCase
import lib.UserPreferences
import views.UserPreferencesView
import lib.Validation.{SuccessMessage, ErrorMessage, FeedbackMessage}

@RunWith(classOf[JUnitRunner])
class UserPreferencesControllerTest extends ControllerTestCase {

  val preferences: UserPreferences = UserPreferences(updateAlertActive = false, maxStaleDays = 2)

  override def controller = new ControllerFilter with UserPreferencesController {
    override def newVersionDetailFetcher = null
    override def userPreferences = preferences
    override def updateUserPreferences(userPreferences: UserPreferences) {}
  }

  test("Should display user preferences") {
    get("/user-preferences") {
      response.status should equal(200)
      result.isInstanceOf[views.UserPreferencesView] should be(true)

      val view = result.asInstanceOf[UserPreferencesView]
      view.userPreferences should be theSameInstanceAs(preferences)
    }
  }

  test("Should submit user preferences") {
    post("/user-preferences", ("enable-update-checks", "on"), ("max-stale-days", "123")) {
      response.status should equal(200)

      val view = result.asInstanceOf[UserPreferencesView]
      view.userPreferences.updateAlertActive should be(true)
      view.userPreferences.maxStaleDays should equal(123)

      view.messages should contain (FeedbackMessage(SuccessMessage, "Your preferences have been updated.", None))
    }
  }

  test("Should submit user preferences fail with invalid data") {
    post("/user-preferences", ("max-stale-days", "-123")) {
      response.status should equal(200)

      val view = result.asInstanceOf[UserPreferencesView]
      view.userPreferences.updateAlertActive should be(false)
      view.userPreferences.maxStaleDays should equal(2)

      view.messages should contain (FeedbackMessage(ErrorMessage, "'-123' must be zero or positive", Some("max-stale-days")))
    }
  }
}