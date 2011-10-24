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

import scala.xml.Text
import scala.util.Random
import bgp.preview._
import net.ripe.commons.certification.validation.roa.RouteValidityState
import net.ripe.ipresource.Asn

class BgpPreviewView(validatedAnnouncements: Set[ValidatedAnnouncement]) extends View with ViewHelpers {

  val MAX_RESULTS = 2000;

  def tab = Tabs.BgpPreviewTab
  def title = Text("BGP Preview")
  def body = {
    <div>
      This page provides a preview of the likely rpki validity states your routers will
	  associate with BGP announcements. This preview is based on:
      <ul>
        <li>BGP announcements that are widely (>5 peers) <a href="http://www.ris.ripe.net/dumps/">seen</a> by RIS</li>
        <li>Validation rules defined in the <a href="http://tools.ietf.org/html/draft-ietf-sidr-roa-validation-10#section-2">IETF standard</a>.</li>
        <li>The validated ROAs found by this validator after applying your filters and additional whitelist entries</li>
      </ul>
    </div>
    <table id="roas-table" class="zebra-striped" style="display: none;">
      <thead>
        <tr>
          <th>ASN</th>
          <th>Prefix</th>
          <th>Validity</th>
        </tr>
      </thead>
      <tbody>
        {
          {validatedAnnouncements filter {
              case ValidatedAnnouncement(asn, prefix, validity) => {
                validity != RouteValidityState.UNKNOWN
//                asn.equals(Asn.parse("3333"))
              }
              case _ => false
            }
          }.take(MAX_RESULTS) map (announcement => {
            <tr>
              <td> { announcement.asn } </td>
              <td> { announcement.prefix } </td>
              <td> { announcement.validity } </td>
            </tr>
          })
        }
      </tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('#roas-table').dataTable({
        "sPaginationType": "full_numbers"
    }).show();
});
// --></script>
  }

}
