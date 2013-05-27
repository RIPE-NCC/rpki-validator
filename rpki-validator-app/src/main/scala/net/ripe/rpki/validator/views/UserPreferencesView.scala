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

import scala.xml._
import lib.UserPreferences
import lib.Validation._

import controllers.UserPreferencesController

class UserPreferencesView(val userPreferences: UserPreferences, val messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {

  private val fieldNameToText = Map("enable-update-checks" -> "Check for updates", "max-stale-days" -> "Maximum days out of date")

  def tab = Tabs.UserPreferencesTab

  def title = Text("User Preferences")

  def body = {

    <div>{ renderMessages(messages, fieldNameToText) }</div>
    <div class="well">
      <form method="POST" class="form-stacked">
        <fieldset>
          <div>
            <label class="checkbox">
              {
                userPreferences.updateAlertActive match {
                  case true => <input name="enable-update-checks" type="checkbox" checked="checked"/>
                  case false => <input name="enable-update-checks" type="checkbox"/>
                }
              }
              Automatically check for new versions of this validator
            </label>
            <label class="checkbox">
              Accept repositories that are no longer updated for up to
              <span rel="twipsy" data-original-title="Increasing this number means that you are less strict about out-of-date repositories, but this means you are more vulnerable to replay attacks. If in doubt, you can leave this on the default setting of 0.">
                <input type="number" class="span2" min="0" name="max-stale-days" value={ Text(userPreferences.maxStaleDays.toString) }/>
              </span>
              days.
            </label>
            <label class="checkbox">
              {
                userPreferences.enableFeedback match {
                  case Some(true) => <input name="enable-feedback" type="checkbox" checked="checked"/>
                  case _ => <input name="enable-feedback" type="checkbox"/>
                }
              }
              Submit performance data to the RIPE NCC (<a href="https://www.ripe.net/certification/rpki-validator-metrics">Learn More&hellip;</a>)
            </label>
          </div>
          <div>
            <br/>
            <button type="submit" class="btn primary">Update Preferences</button>
          </div>
        </fieldset>
      </form>
    </div>
    <script><!--
$(function () {
  $('[rel=twipsy]').twipsy({
    "live": true
  });
});
//--></script>
  }
}

object EnableFeedbackPrompt {

  def optionalFeedBackEnablePrompt(userPreferences: UserPreferences) = userPreferences.enableFeedback match {
    case None =>
      <div>
        Do you want to help the RIPE NCC gather information on the efficiency and reliability of the global RPKI system
        by submitting performance data?<br/>
        <a href="https://www.ripe.net/certification/rpki-validator-metrics">Learn More&hellip;</a>
        { createEnableOrDisableButton(userPreferences, enable = true) }{ createEnableOrDisableButton(userPreferences, enable = false) }
      </div>
    case _ =>
      NodeSeq.Empty
  }

  private def createEnableOrDisableButton(userPreferences: UserPreferences, enable: Boolean) = {
    // See application.css for style of this form
    <form method="POST" action={ UserPreferencesController.baseUrl } class="inline-feedback-option-form">
      {
        userPreferences.updateAlertActive match {
          case true => <input type="hidden" name="enable-update-checks" value="1"/>
          case _  => NodeSeq.Empty
        }
      }
      <input type="hidden" name="max-stale-days" value={ Text(userPreferences.maxStaleDays.toString) } />

      {
        enable match {
          case true => {
              <input type="hidden" name="enable-feedback" value="1" />
              <button type="submit" class="btn small">Yes</button>
          }
          case false => {
              <button type="submit" class="btn small">No</button>
          }
        }
      }
    </form>
  }

}

