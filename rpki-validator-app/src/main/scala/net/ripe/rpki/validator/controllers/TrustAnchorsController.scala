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

import scalaz._, Scalaz._
import models._
import lib.Validation._
import net.ripe.rpki.validator.util.TrustAnchorLocator

trait TrustAnchorsController extends ApplicationController {
  protected def trustAnchors: TrustAnchors
  protected def updateTrustAnchorState(locator: TrustAnchorLocator, enabled: Boolean)
  protected def validatedObjects: ValidatedObjects
  protected def startTrustAnchorValidation(trustAnchors: Seq[String])

  get("/trust-anchors") {
    new views.TrustAnchorsView(trustAnchors, validatedObjects.validationStatusCounts, messages = feedbackMessages)
  }

  post("/trust-anchors/update") {
    validateParameter("name", required(trustAnchorByName)) match {
      case Success(trustAnchor) =>
        startTrustAnchorValidation(Seq(trustAnchor.name))
        redirectWithFeedbackMessages("/trust-anchors", Seq(InfoMessage("Started validation of trust anchor " + trustAnchor.name)))
      case Failure(_) =>
        startTrustAnchorValidation(trustAnchors.all.map(_.name))
        redirectWithFeedbackMessages("/trust-anchors", Seq(InfoMessage("Started validation of all trust anchors.")))
    }
  }

  post("/trust-anchors/toggle") {
    validateParameter("name", required(trustAnchorByName)) match {
      case Success(trustAnchor) =>
        val enabled = !trustAnchor.enabled
        updateTrustAnchorState(trustAnchor.locator, enabled)
        if (enabled) {
          startTrustAnchorValidation(Seq(trustAnchor.name))
          redirectWithFeedbackMessages("/trust-anchors", Seq(InfoMessage("Trust anchor '" + trustAnchor.name + "' has been enabled.")))
        } else {
          redirectWithFeedbackMessages("/trust-anchors", Seq(InfoMessage("Trust anchor '" + trustAnchor.name + "' has been disabled.")))
        }
      case Failure(feedbackMessage) =>
        redirectWithFeedbackMessages("/trust-anchors", feedbackMessage)
    }
  }

  private def trustAnchorByName(s: String): Validation[String, TrustAnchor] =
    trustAnchors.all.find(_.name == s).map(_.success).getOrElse(("No trust anchor with name '" + s + "' found").fail)
}
