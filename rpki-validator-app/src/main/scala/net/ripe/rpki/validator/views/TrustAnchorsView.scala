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
package views

import org.joda.time._
import org.joda.time.format.PeriodFormat
import scala.xml.Text
import scala.xml.NodeSeq
import scala.collection.SortedMap
import lib.DateAndTime._
import lib.Validation._
import models._

class TrustAnchorsView(trustAnchors: TrustAnchors, now: DateTime = new DateTime, messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {
  def tab = Tabs.TrustAnchorsTab
  def title = Text("Configured Trust Anchors")
  def body = {
    <div>{ renderMessages(messages, identity) }</div>
    <table id="trust-anchors" class="zebra-striped">
      <thead>
        <th>CA Name</th>
        <th>Subject</th>
        <th>Expires in</th>
        <th>Last updated</th>
        <th>Next update in</th>
        <th>
          <form method="POST" action={ tab.url + "/update" } style="padding:0;margin:0;">
            {
              if (trustAnchors.all.forall(_.status.isRunning))
                <input type="submit" class="btn primary span2" value="update all" disabled="disabled"/>
              else
                <input type="submit" class="btn primary span2" value="update all"/>
            }
          </form>
        </th>
      </thead>
      <tbody>{
        for (ta <- sortedTrustAnchors) yield {
          <tr>
            <td>{ ta.name }</td>{
              ta.certificate match {
                case Some(certificate) =>
                  val notValidAfter = certificate.getCertificate().getValidityPeriod().getNotValidAfter()
                  <td>{ certificate.getCertificate().getSubject() }</td>
                  <td><span title={ notValidAfter.toString() }>{ expiresIn(notValidAfter) }</span></td>
                case None =>
                  <td></td>
                  <td></td>
              }
            }{
              ta.lastUpdated match {
                case Some(lastUpdated) =>
                  <td><span title={ lastUpdated.toString() }>{ periodInWords(new Period(lastUpdated, now).withMillis(0), number = 1) + " ago" }</span></td>
                case None =>
                  <td></td>
              }
            }{
              ta.status match {
                case Running(description) =>
                  <td>{ description }</td>
                  <td style="text-align: center;"><img src="/images/spinner.gif"/></td>
                case Idle(nextUpdate) =>
                  <td><span title={ nextUpdate.toString() }>{ if (now <= nextUpdate) periodInWords(new Period(now, nextUpdate), number = 1) else "any moment" }</span></td>
                  <td>
                    <form method="POST" action={ tab.url + "/update" } style="padding:0;margin:0;">
                      <input type="hidden" name="name" value={ ta.locator.getCaName() }/>
                      <input type="submit" class="btn span2" value="update"/>
                    </form>
                  </td>
              }
            }
          </tr>
        }
      }</tbody>
    </table>
    <script><!--
$(function () {
  var refresh = function() {
    $.ajax({
      url: "/trust-anchors",
      dataType: "html",
      success: function (data) {
        var updatedTable = $(data).filter("#trust-anchors");
        $("#trust-anchors").replaceWith(updatedTable);
      }
    });
  };
  setInterval(refresh, 10000);
});
//--></script>
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
