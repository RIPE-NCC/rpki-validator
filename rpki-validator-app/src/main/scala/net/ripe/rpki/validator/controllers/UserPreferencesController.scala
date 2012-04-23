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

import lib.{ UserPreferences, SoftwareUpdateChecker }
import lib.Validation._
import scalaz._
import Scalaz._

trait UserPreferencesController extends ApplicationController with SoftwareUpdateChecker {

  val baseUrl = "/user-preferences"

  def updateUserPreferences(userPreferences: UserPreferences)
  def userPreferences: UserPreferences

  get(baseUrl) {
    new views.UserPreferencesView(userPreferences, messages = feedbackMessages)
  }

  post(baseUrl) {
    submittedUserPreferences match {
      case Success(userPreferences) =>
        updateUserPreferences(userPreferences)
        new views.UserPreferencesView(userPreferences, messages = Seq(SuccessMessage("Your preferences have been updated. Changes will take effect on next update.")))
      case Failure(errors) =>
        new views.UserPreferencesView(userPreferences, messages = errors)
    }
  }

  private def submittedUserPreferences: ValidationNEL[FeedbackMessage, UserPreferences] = {
    val enableUpdateChecks = validateParameter("enable-update-checks", parseCheckBoxValue)

    val maxStale = params.get("enable-staleness-check") match {
      case Some(_) => validateParameter("max-stale-days", required(parseNonNegativeInt))
      case None => 0.success
    }

    (enableUpdateChecks |@| maxStale).apply(UserPreferences)
  }
}
