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

import scalaz._,Scalaz._

import org.scalatra._
import lib.Validation._
import views.HomeView
import net.ripe.rpki.validator.authentication.AuthenticationSupport

trait ApplicationController extends ScalatraBase with FlashMapSupport with MethodOverride with AuthenticationSupport {
  get("/") {
    new HomeView()
  }

  protected[this] def feedbackMessages: Seq[FeedbackMessage] = flash.get("feedback").map(_.asInstanceOf[Seq[FeedbackMessage]]).getOrElse(Seq.empty)

  protected[this] def redirectWithFeedbackMessages(url: String, messages: Seq[FeedbackMessage]) {
    flash("feedback") = messages
    redirect(url)
  }

  protected[this] def validateParameter[A](name: String, validator: Option[String] => Validation[String, A]): ValidationNEL[FeedbackMessage, A] = {
    val value = params.get(name).filterNot(_.isEmpty)
    val result = validator(value)
    liftFailErrorMessage(result, Some(name))
  }

  override def post(transformers: RouteTransformer*)(action: => Any) = super.post(transformers:_*) { authenticatedAction(action) }
  override def put(transformers: RouteTransformer*)(action: => Any) = super.put(transformers:_*) { authenticatedAction(action) }
  override def delete(transformers: RouteTransformer*)(action: => Any) = super.delete(transformers:_*) { authenticatedAction(action) }
}
