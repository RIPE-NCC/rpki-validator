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

import org.joda.time._
import scala.math.Ordering.Implicits._
import scala.xml.Text
import scala.xml.NodeSeq
import lib.DateAndTime._
import lib.Validation._
import models._
import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.validator.util.TrustAnchorLocator

class TrustAnchorsView(trustAnchors: TrustAnchors, validationStatusCounts: Map[TrustAnchorLocator, Map[ValidationStatus, Int]], now: DateTime = new DateTime, messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {
  def tab = Tabs.TrustAnchorsTab
  def title = Text("Configured Trust Anchors")
  def body = {
    <div>{ renderMessages(messages, identity) }</div>
    <table id="trust-anchors" class="zebra-striped">
      <thead>
        <th>Enabled</th>
        <th>Trust anchor</th>
        <th>Processed Items</th>
        <th>Expires in</th>
        <th>Last updated</th>
        <th>Next update in</th>
        <th class="center">
          <form method="POST" action={ tab.url + "/update" } style="padding:0;margin:0;">
            {
            if ((trustAnchors.all.forall(_.status.isRunning)) || (trustAnchors.all.forall(!_.enabled)))
                <input type="submit" class="btn primary span2" value="Update all" disabled="disabled"/>
            else
                <input type="submit" class="btn primary span2" value="Update all"/>
            }
          </form>
        </th>
      </thead>
      <tbody>{
        for (ta <- sortedTrustAnchors) yield {
          <tr>
            <td class="center">
              <form method="POST" action={ tab.url + "/toggle" } style="padding:0;margin:0;">
                  <input type="hidden" name="name" value={ ta.locator.getCaName }/>
                {
                if (ta.enabled)
                    <input name="enable-ta" type="checkbox" checked="checked" onclick="this.form.submit();"/>
                else
                    <input name="enable-ta" type="checkbox" onclick="this.form.submit();"/>
                }
              </form>
            </td>
            <td><span rel="twipsy" data-original-title={ ta.certificate.map(_.getSubject.toString).getOrElse("") }>{ ta.name }</span></td>
            <td nowrap="nowrap">{ renderCounters(ta, validationStatusCounts.getOrElse(ta.locator, Map.empty)) }</td>{
              ta.certificate match {
                case Some(certificate) =>
                  val notValidAfter = certificate.getValidityPeriod.getNotValidAfter
                  <td><span rel="twipsy" data-original-title={ formatDateTime(notValidAfter) }>{ expiresIn(notValidAfter) }</span></td>
                case None =>
                  <td></td>
              }
            }{
              if (ta.enabled) {
                ta.lastUpdated match {
                  case Some(lastUpdated) =>
                    val manifestStale = ta.manifestNextUpdateTime.flatMap { dt => if (dt.isBefore(now)) Some("Manifest has been stale for " + periodInWords(new Period(dt, now))) else None }
                    val crlStale = ta.crlNextUpdateTime.flatMap { dt => if (dt.isBefore(now)) Some("CRL has been stale for " + periodInWords(new Period(dt, now))) else None }
                    val warnings = Seq(manifestStale, crlStale).flatten
                    <td><span rel="twipsy" data-original-title={ formatDateTime(lastUpdated) }>{ periodInWords(new Period(lastUpdated, now).withMillis(0), number = 1) + " ago" }</span>{ if (warnings.isEmpty) NodeSeq.Empty else <span rel="twipsy" data-original-title={ warnings.mkString(", ") }>&nbsp;<img align="center" src="/images/warningS.png"/></span> } </td>
                  case None =>
                    <td></td>
                }
              } else {
                <td></td>
              }
            }{
              if (ta.enabled) {
                ta.status match {
                  case Running(description) =>
                    <td>{ description }</td>
                      <td style="text-align: center;"><img src="/images/spinner.gif"/></td>
                  case Idle(nextUpdate, errorMessage) =>
                    <td><span rel="twipsy" data-original-title={ formatDateTime(nextUpdate) }>{
                      if (ta.enabled)
                        if (now <= nextUpdate) periodInWords(new Period(now, nextUpdate), number = 1) else "any moment"
                      else
                        ""
                      }</span>{
                      errorMessage.map(text => <span rel="twipsy" data-original-title={ text }>&nbsp;<img align="center" src="/images/warningS.png"/></span>).getOrElse(NodeSeq.Empty)
                      }</td>
                      <td class="center">
                        <form method="POST" action={ tab.url + "/update" } style="padding:0;margin:0;">
                            <input type="hidden" name="name" value={ ta.locator.getCaName }/>
                            <input type="submit" class="btn span2" value="Update"/>
                        </form>
                      </td>
                }
              } else {
                <td></td>
                <td></td>
              }
            }
          </tr>
        }
      }</tbody>
    </table>
    <script><!--
$(function () {
  $('[rel=twipsy]').twipsy({
    "live": true
  });
  var refresh = function() {
    $.ajax({
      url: "/trust-anchors/refresh",
      dataType: "html",
      success: function (data) {
        var updatedTable = $(data).filter("#trust-anchors");
        $("#trust-anchors").replaceWith(updatedTable);
        $("div.twipsy").fadeOut();
      }
    });
  };
  setInterval(refresh, 10000);
});
//--></script>
  }

  private def renderCounters(ta: TrustAnchor, counters: Map[ValidationStatus, Int]) = {
    def badge(level: String, count: Int) = {
      val clazz = "object-counter label " + level
      val style = if (count > 0) "" else "opacity: 0.25;"
      val helpText = "Click to view monitor page"
      <span rel="twipsy" data-original-title={ helpText }>
        <a href={ Tabs.TrustAnchorMonitorTab.url + "/" + ta.identifierHash }>{<span class={ clazz } style={ style }>{ count }</span>}</a>
      </span>
    }

    <span>
      { badge("success", counters.getOrElse(ValidationStatus.PASSED, 0)) }
      { badge("warning", counters.getOrElse(ValidationStatus.WARNING, 0)) }
      { badge("important", counters.getOrElse(ValidationStatus.ERROR, 0)) }
    </span>
  }

  private def expiresIn(notValidAfter: DateTime): NodeSeq = {
    if (now.isBefore(notValidAfter)) {
      Text(periodInWords(new Period(now, notValidAfter)))
    } else {
      <strong>EXPIRED</strong>
    }
  }
  private def sortedTrustAnchors = trustAnchors.all.sortBy(_.name)
}
