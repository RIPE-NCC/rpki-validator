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
package controllers

import net.ripe.ipresource.IpRange
import scalaz._
import Scalaz._
import lib.Validation._
import models._
import views.FiltersView

trait FiltersController extends ApplicationController {
  
  protected def filters: Filters
  protected def addFilter(filter: IgnoreFilter): Unit
  protected def removeFilter(filter: IgnoreFilter): Unit
  protected def filterExists(filter: IgnoreFilter): Boolean = filters.entries.contains(filter)
  protected def roas: Roas

  private def baseUrl = views.Tabs.FiltersTab.url
  
  private def getCurrentRtrPrefixes(): Iterable[RtrPrefix] = roas.getValidatedRtrPrefixes

  get(baseUrl) {
    new FiltersView(filters, getCurrentRtrPrefixes, messages = feedbackMessages)
  }

  post(baseUrl) {
    submittedFilter match {
      case Success(entry) =>
        if (filterExists(entry))
          new FiltersView(filters, getCurrentRtrPrefixes, params, Seq(ErrorMessage("filter already exists")))
        else {
          addFilter(entry)
          redirectWithFeedbackMessages(baseUrl, Seq(SuccessMessage("The prefix has been added to the filters.")))
        }
      case Failure(errors) =>
        new FiltersView(filters, getCurrentRtrPrefixes, params, errors)
    }
  }

  delete(baseUrl) {
    submittedFilter match {
      case Success(entry) =>
        if (filterExists(entry)) {
          removeFilter(entry)
          redirectWithFeedbackMessages(baseUrl, Seq(SuccessMessage("The prefix has been removed from the filters.")))
        } else {
          new FiltersView(filters, getCurrentRtrPrefixes, params, Seq(ErrorMessage("filter no longer exists")))
        }
      case Failure(errors) =>
        // go away hacker!
        new FiltersView(filters, getCurrentRtrPrefixes, params, errors)
    }
  }

  private def submittedFilter: ValidationNEL[FeedbackMessage, IgnoreFilter] = {
    validateParameter("prefix", required(parseIpPrefix)) map IgnoreFilter
  }
  
}
