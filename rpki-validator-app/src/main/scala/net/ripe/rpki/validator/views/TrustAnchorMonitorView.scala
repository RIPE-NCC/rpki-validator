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

import scala.xml.Text
import lib.Validation._
import net.ripe.rpki.validator.models
import models._
import net.ripe.rpki.commons.validation.{ValidationString, ValidationStatus}

class TrustAnchorMonitorView(ta: TrustAnchor, validatedObjectsOption: Option[Seq[ValidatedObject]], messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {

  val MaximumErrorCount = 10
  val MaximumRsyncErrors = 10

  def tab = Tabs.TrustAnchorsTab
  def title = Text(s"Monitoring for ${ta.name}")

  val size = validatedObjectsOption.getOrElse(Seq.empty).size

  def numberOfObjectsWithStatus(status: ValidationStatus) = validatedObjectsOption match {
    case None => 0
    case Some(validatedObjects) => validatedObjects.count(vo => vo.validationStatus.equals(status))
  }

  val hasProblemValidatingTa = validatedObjectsOption match {
    case Some(validatedObject) => validatedObject.exists(vo => vo.uri == ta.locator.getCertificateLocation && !vo.isValid)
    case None => false
  }

  val hasUnexpectedDrop = validatedObjectsOption match {
    case Some(validatedObjects) => validatedObjects.exists(vo => vo.checks.map(_.getKey).contains(ValidationString.VALIDATOR_REPOSITORY_OBJECT_DROP))
    case None => false
  }

  val hasTooManyErrors = validatedObjectsOption match {
    case Some(validatedObjects) => numberOfObjectsWithStatus(ValidationStatus.ERROR) >= MaximumErrorCount
    case None => false
  }

  val hasTooManyRsyncFetchFailures = validatedObjectsOption match {
    case Some(validatedObjects) => validatedObjects.flatMap(_.checks).count(_.getKey == ValidationString.VALIDATOR_RSYNC_COMMAND) >= MaximumRsyncErrors
    case None => false
  }

  val hasWarningsOrErrors = numberOfObjectsWithStatus(ValidationStatus.WARNING) + numberOfObjectsWithStatus(ValidationStatus.ERROR) > 0

  val overallHealthy = !hasProblemValidatingTa && !hasUnexpectedDrop && !hasTooManyErrors && !hasTooManyRsyncFetchFailures

  def badge(level: String, text: String, opaque: Boolean = false) = {
    val clazz = "object-counter label " + level
    val style = if (opaque) "opacity: 0.25;" else ""
    <span class={ clazz } style={ style }>{ text }</span>
  }
  
  def checkToOkOrAlertBadge(isOkay: Boolean) = {
    val level = if (isOkay) "success" else "important"
    val text = if (isOkay) "OK" else "ALERT"
    badge(level, text)
  }

  def numberBadge(level: String, number: Int) = {
    badge(level, number.toString, number == 0)
  }

  def renderValidationDetails = {
    <h3>Validation violations</h3>
      <table id="validation-details-table" class="zebra-striped" style="display: none;" data-source={ s"${Tabs.TrustAnchorMonitorTab.url}/validation-detail/${ta.identifierHash}" }>
        <thead>
          <tr>
            <th>Trust Anchor</th>
            <th>Object</th>
            <th>Validity</th>
            <th>Validation Message</th>
          </tr>
        </thead>
        <tbody>
        </tbody>
      </table>
      <script>
        {
        <!--
$(document).ready(function() {
  $('[rel=twipsy]').twipsy({
    "live": true
  });
  $('#validation-details-table').dataTable({
        "sPaginationType": "full_numbers",
        "bProcessing": true,
        "bServerSide": true,
        "sAjaxSource": $('#validation-details-table').attr('data-source')
    }).show();
});
// -->}
      </script>
  }



  def body = {
    <div>{ renderMessages(messages, identity) }</div>
    <h2 class="center">{ checkToOkOrAlertBadge(overallHealthy) }</h2>
    <div>

      <h3>Checks</h3>
      <table id="errors" class="zebra-striped">
        <tr><td>Could validate trust anchor using trust anchor locator</td><td> { checkToOkOrAlertBadge(!hasProblemValidatingTa) } </td></tr>
        <tr><td>Unexplained object count drop since last validation run (10% drop combined with errors)</td><td> { checkToOkOrAlertBadge(!hasUnexpectedDrop) } </td></tr>
        <tr><td>More than { MaximumErrorCount } errors seen</td><td> { checkToOkOrAlertBadge(!hasTooManyErrors) } </td></tr>
        <tr><td>More than { MaximumRsyncErrors } rsync fetch failures seen</td><td> { checkToOkOrAlertBadge(!hasTooManyRsyncFetchFailures) } </td></tr>
      </table>

      <h3>Statistics for the last validation run</h3>
      <table id="details" class="zebra-striped">
        <tr><td>Objects that passed validation correctly</td><td>{ numberBadge("success", numberOfObjectsWithStatus(ValidationStatus.PASSED)) }</td></tr>
        <tr><td>Objects that passed validation with warnings</td><td>{ numberBadge("warning", numberOfObjectsWithStatus(ValidationStatus.WARNING)) }</td></tr>
        <tr><td>Objects that did not pass validation</td><td>{ numberBadge("important", numberOfObjectsWithStatus(ValidationStatus.ERROR)) }</td></tr>
      </table>

      { if (hasWarningsOrErrors) { renderValidationDetails } }

    </div>
  }

}
