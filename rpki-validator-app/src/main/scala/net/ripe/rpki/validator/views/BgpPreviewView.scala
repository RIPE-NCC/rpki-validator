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
import scala.xml.Text
import bgp.preview._
import lib.DateAndTime._

class BgpPreviewView(bgpAnnouncementSets: Seq[BgpAnnouncementSet], search: String) extends View with ViewHelpers {

  val now = new Instant()

  private def lastUpdated = bgpAnnouncementSets.flatMap(_.lastModified).toList match {
    case Nil => <span>is currently being loaded</span>
    case times => <span>was last updated <span rel="twipsy" data-original-title={formatDateTime(times.max)}>{periodInWords(new Period(times.max, now), 2)} ago</span></span>
  }

  def tab = Tabs.BgpPreviewTab
  def title = Text("BGP Preview")
  def body = {
    <div class="alert-message block-message info" data-alert="alert">
      <a class="close" href="#">×</a>
      <p>
        This page provides a <strong>preview</strong> of the likely RPKI validity states your routers will associate
        with BGP announcements. This preview is based on:
      </p>
      <ul>
        <li>The <a href="http://www.ris.ripe.net/dumps/">RIPE NCC Route Collector information</a> that <span id="bgp-dump-last-updated">{lastUpdated}</span>.</li>
        <li>BGP announcements that are seen by { BgpAnnouncementValidator.VISIBILITY_THRESHOLD } or more peers.</li>
        <li>The validation rules defined in <a href="http://tools.ietf.org/html/rfc6483#section-2">RFC 6483</a>.</li>
        <li>The validated ROAs found by this RPKI Validator after applying your filters and additional whitelist entries.</li>
      </ul>
      <br/>
      <p>
        Please note that the BGP announcements your routers see may differ from the ones listed here.
      </p>
    </div>
    <table id="bgp-preview-table" class="zebra-striped" style="display: none;" data-search={ search }>
      <thead>
        <tr>
          <th width="200px">ASN</th>
          <th>Prefix</th>
          <th width="200px">Validity</th>
        </tr>
      </thead>
      <tbody>
      </tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('#bgp-preview-table').dataTable({
        "oSearch": {"sSearch": $('#bgp-preview-table').attr('data-search')},
        "sPaginationType": "full_numbers",
        "bProcessing": true,
        "bServerSide": true,
        "sAjaxSource": "bgp-preview-data"
    }).show();
  $('[rel=popover]').popover({
    "live": true,
    "html": true,
    "placement": "above",
    "offset": 10
  }).live('click', function (e) {
    e.preventDefault();
  });
  $('[rel=twipsy]').twipsy({
    "live": true
  });
  var refreshBgpRisDumps = function() {
    $.ajax({
      url: "/bgp-preview",
      dataType: "html",
      success: function (data) {
        var updated = $(data).find("#bgp-dump-last-updated");
        $("#bgp-dump-last-updated").replaceWith(updated);
      }
    });
  };
  setInterval(refreshBgpRisDumps, 10000);
});
// --></script>
  }

}
