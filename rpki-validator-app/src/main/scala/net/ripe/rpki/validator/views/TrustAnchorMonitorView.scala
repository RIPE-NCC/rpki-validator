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

import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.validator.lib.Validation._
import net.ripe.rpki.validator.models._

import scala.xml.Text

class TrustAnchorMonitorView(ta: TrustAnchor, trustAnchorValidations: TrustAnchorValidations,
                             messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {

  val MaximumErrorCount = 10
  val MaximumErrorFraction = .1
  val MaximumFetchErrors = 1

  def tab = Tabs.TrustAnchorsTab
  def title = Text(s"Monitoring for ${ta.name}")

  val validatedObjects = trustAnchorValidations.validatedObjects
  val size = trustAnchorValidations.validatedObjects.size

  def numberOfObjectsWithStatus(status: ValidationStatus) = validatedObjects.count(vo => vo.validationStatus.equals(status))

  private def taCertLocation = Option(ta.locator.getFetchedCertificateUri).map(_.toString)

  val hasProblemValidatingTa = taCertLocation.exists(uri =>
    validatedObjects.exists(vo => !vo.isValid && vo.subjectChain == uri))

  val hasUnexpectedDrop = trustAnchorValidations.objectCountDropObserved.isDefined

  val hasTooManyErrors = numberOfObjectsWithStatus(ValidationStatus.ERROR) >= MaximumErrorCount

  val hasTooHighErrorFraction = {
    val objectsInError = numberOfObjectsWithStatus(ValidationStatus.ERROR)
    val totalObjects = validatedObjects.size
    totalObjects != 0 && objectsInError.toFloat / totalObjects > MaximumErrorFraction
  }

  val hasFetchFailures = validatedObjects.flatMap(_.checks).count(_.getStatus == ValidationStatus.FETCH_ERROR) > 0

  val hasWarningsOrErrors = numberOfObjectsWithStatus(ValidationStatus.WARNING) + numberOfObjectsWithStatus(ValidationStatus.ERROR) > 0

  val overallHealthy = !hasProblemValidatingTa && !hasUnexpectedDrop && !hasTooManyErrors && !hasTooHighErrorFraction

  def badge(level: String, text: String, opaque: Boolean = false) = {
    val clazz = "object-counter label " + level
    val style = if (opaque) "opacity: 0.25;" else ""
    <span class={ clazz } style={ style }>{ text }</span>
  }

  def checkToOverallHealthBadge(isOkay: Boolean) = {
    checkToTextBadge(isOkay, passedText = "Overall health: OK - All checks were successful", failedText = "Overall health: ALERT - One or more checks failed")
  }

  def checkToYesOrAlertBadge(isOkay: Boolean) = {
    checkToTextBadge(isOkay, passedText = "YES", failedText = "ALERT")
  }

  def checkToTextBadge(isOkay: Boolean, passedText: String = "OK", failedText: String = "ALERT") = {
    val level = if (isOkay) "success" else "important"
    val text = if (isOkay) passedText else failedText
    badge(level, text)
  }

  def numberBadge(level: String, number: Int) = {
    badge(level, number.toString, number == 0)
  }


  def renderFetchDetails = {
    <h3>Fetch errors</h3>
      <table id="fetch-details-table" class="zebra-striped" style="display: none;" data-source={ s"${Tabs.TrustAnchorMonitorTab.url}/fetch-detail/${ta.identifierHash}" }>
        <thead>
          <tr>
            <th>Object</th>
            <th>Message</th>
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
  $('#fetch-details-table').dataTable({
        "sPaginationType": "full_numbers",
        "bProcessing": true,
        "bServerSide": true,
        "sAjaxSource": $('#fetch-details-table').attr('data-source')
    }).show();
});
// -->}
      </script>
  }


  def renderValidationDetails = {
    <h3>Validation violations</h3>
      <table id="validation-details-table" class="zebra-striped" style="display: none;"
             data-source={ s"${Tabs.TrustAnchorMonitorTab.url}/validation-detail/${ta.identifierHash}" }>
        <thead>
          <tr>
            <th>Object</th>
            <th>Severity</th>
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
      <h2 class="center"><span id="healthcheck-result">{ checkToOverallHealthBadge(overallHealthy) }</span></h2>
      <div>

        <h3>Checks</h3>
        <table id="errors" class="zebra-striped">
          <tr><td>Trust anchor could be validated using trust anchor locator</td><td> { checkToYesOrAlertBadge(!hasProblemValidatingTa) } </td></tr>
          <tr><td>Object count has not dropped more than 10% since the last validation</td><td> { checkToYesOrAlertBadge(!hasUnexpectedDrop) } </td></tr>
          <tr><td>Fewer than { MaximumErrorCount } validation errors</td><td> { checkToYesOrAlertBadge(!hasTooManyErrors) } </td></tr>
          <tr><td>Less than { (MaximumErrorFraction * 100).round }% of objects have a validation error</td><td> { checkToYesOrAlertBadge(!hasTooHighErrorFraction) } </td></tr>
          <tr><td>All objects fetched successfully</td><td> { if(hasFetchFailures) badge("warning", "WARNING") else badge("success", "YES") } </td></tr>
        </table>

      <h3>Statistics for the last validation run</h3>
      <table id="details" class="zebra-striped">
        <tr><td>Objects that passed validation correctly</td><td>{ numberBadge("success", numberOfObjectsWithStatus(ValidationStatus.PASSED)) }</td></tr>
        <tr><td>Objects that passed validation with warnings</td><td>{ numberBadge("warning", numberOfObjectsWithStatus(ValidationStatus.WARNING)) }</td></tr>
        <tr><td>Objects that did not pass validation</td><td>{ numberBadge("important", numberOfObjectsWithStatus(ValidationStatus.ERROR)) }</td></tr>
      </table>

      { if (hasWarningsOrErrors) { renderValidationDetails } }
      { if (hasFetchFailures) { renderFetchDetails } }

    </div>
  }

}
