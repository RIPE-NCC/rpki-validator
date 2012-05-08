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

import scalaz._
import Scalaz._
import scala.xml._
import models._
import lib.Validation._
import bgp.preview.BgpValidatedAnnouncement
import net.ripe.commons.certification.validation.roa.RouteValidityState

class WhitelistView(whitelist: Whitelist, validatedAnnouncements: Seq[BgpValidatedAnnouncement], params: Map[String, String] = Map.empty, messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {
  private val fieldNameToText = Map("asn" -> "Origin", "prefix" -> "Prefix", "maxPrefixLength" -> "Maximum prefix length")

  def tab = Tabs.WhitelistTab
  def title = Text("Whitelist")
  def body = {
    <div>{ renderMessages(messages, fieldNameToText) }</div>
    <div class="alert-message block-message info" data-alert="alert">
    <a class="close" href="#">×</a>
      <p>
        By adding a whitelist entry you can manually authorize an ASN to announce a prefix in addition to validated ROAs
        from the repository.
      </p>
      <p>
        Please note that whitelist entries may <strong>invalidate</strong> announcements for this prefix from other ASNs,
        just like ROAs. This may be intentional (you are whitelisting ASN A, ASN B is hijacking), or not (ASN B should also
        be authorised, or you made a mistake). When you create a whitelist entry here, make sure to check the table below
        for a report on prefixes validated / invalidated by this entry and verify that no unintentional side effects occured.
        E.g. create an additional entry for another ASN, or delete this entry and re-create it as needed.
      </p>
    </div>
    <h2>Add entry</h2>
    <div class="well">
      <form method="POST" class="form-stacked">
        <fieldset>
          <div>
            <div class="span4"><label for="announcement-asn">Origin</label></div>
            <div class="span4"><label for="announcement-prefix">Prefix</label></div>
            <div class="span4"><label for="announcement-maxprefixlen">Maximum prefix length</label></div>
            <div class="span4"></div>
          </div>
          <div class="span4">
            <input id="announcement-asn" type="text" name="asn" value={ params.getOrElse("asn", "") } placeholder="ASN (required)"/>
          </div>
          <div class="span4">
            <input id="announcement-prefix" type="text" name="prefix" value={ params.getOrElse("prefix", "") } placeholder="IPv4 or IPv6 prefix (required)"/>
          </div>
          <div class="span4">
            <input id="announcement-maxprefixlen" type="text" name="maxPrefixLength" value={ params.getOrElse("maxPrefixLength", "") } placeholder="Number (optional)"/>
          </div>
          <div class="span2">
            <input type="submit" class="btn primary" value="Add"/>
          </div>
        </fieldset>
      </form>
    </div>
    <div>
      <h2>Current entries</h2>{
        if (whitelist.entries.isEmpty)
          <div class="alert-message block-message"><p>No whitelist entries defined.</p></div>
        else {
          <table id="whitelist-table" class="zebra-striped" style="display: none;">
            <thead>
              <tr>
                <th>Origin</th><th>Prefix</th><th>Maximum Prefix Length</th><th>Validates</th><th>Invalidates</th><th>&nbsp;</th>
              </tr>
            </thead>
            <tbody>{
              for (entry <- whitelist.entries) yield {

                val affectedAnnouncements = validatedAnnouncements.filter { announcement =>
                  entry.prefix.contains(announcement.prefix)
                }

                // Will work because we only match on affected announcements and will have no unknowns
                var (validated, invalidated) = affectedAnnouncements.partition(_.validity == RouteValidityState.VALID)

                // Validates only matches on asn
                validated = validated.filter { _.asn == entry.asn }

                def makeDetailsTable(announcements: Seq[BgpValidatedAnnouncement]) = {
                  <table>
                    <thead>
                      <tr><th>ASN</th><th>Prefix</th></tr>
                    </thead>
                    {
                      for { announcement <- announcements } yield {
                        <tr>
                          <td> { announcement.asn.getValue().toString() } </td>
                          <td> { announcement.prefix.toString() } </td>
                        </tr>
                      }
                    }
                  </table>
                }

                <tr>
                  <td>{ entry.asn.getValue() }</td>
                  <td>{ entry.prefix }</td>
                  <td>{ entry.maxPrefixLength.getOrElse("") }</td>
                  <td>
                    <span rel="popover" data-content={ Xhtml.toXhtml(makeDetailsTable(validated)) } data-original-title="Details">{ validated.size + " announcement(s)" }</span>
                  </td>
                  <td>
                    <span rel="popover" data-content={ Xhtml.toXhtml(makeDetailsTable(invalidated)) } data-original-title="Details">{ invalidated.size + " announcement(s)" }</span>
                  </td>
                  <td>
                    <form method="POST" action="/whitelist" style="padding:0;margin:0;">
                      <input type="hidden" name="_method" value="DELETE"/>
                      <input type="hidden" name="asn" value={ entry.asn.toString }/>
                      <input type="hidden" name="prefix" value={ entry.prefix.toString }/>
                      <input type="hidden" name="maxPrefixLength" value={ entry.maxPrefixLength.map(_.toString).getOrElse("") }/>
                      <input type="submit" class="btn" value="delete"/>
                    </form>
                  </td>
                </tr>
              }
            }</tbody>
          </table>
          <script><!--
$(document).ready(function() {
  $('#whitelist-table').dataTable({
      "sPaginationType": "full_numbers",
      "aoColumns": [
        { "sType": "numeric" },
        null,
        { "sType": "numeric" },
        { "bSortable": false },
        { "bSortable": false },
        { "bSortable": false }
      ]
    }).show();
  $('[rel=popover]').popover({
    "live": true,
    "html": true,
    "placement": "below",
    "offset": 10
  }).live('click', function (e) {
    e.preventDefault();
  });
});
// --></script>
        }
      }
    </div>
  }
}
