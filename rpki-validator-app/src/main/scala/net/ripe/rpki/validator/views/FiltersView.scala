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
import models._
import lib.Validation._

class FiltersView(filters: Filters, getCurrentRtrPrefixes: () => Iterable[RtrPrefix], params: Map[String, String] = Map.empty, messages: Seq[FeedbackMessage] = Seq.empty) extends View with ViewHelpers {
  private val fieldNameToText = Map("prefix" -> "Prefix")

  val currentRtrPrefixes = getCurrentRtrPrefixes()
  
  def tab = Tabs.FiltersTab
  def title = tab.text
  def body = {
    <div>{ renderMessages(messages, fieldNameToText) }</div>
    <div class="alert-message block-message info" data-alert="alert">
    <a class="close" href="#">×</a>
    <p>By adding a filter the validator will ignore any RPKI prefixes that overlap with the filter's prefix.</p>
    </div>
    <h2>Add filter</h2>
    <div class="well">
      <form method="POST" class="form-stacked">
        <fieldset>
          <div>
            <div class="span4"><label for="filter-prefix">Prefix</label></div>
            <div class="span12"></div>
          </div>
          <div class="span4">
            <input id="filter-prefix" type="text" name="prefix" value={ params.getOrElse("prefix", "") } placeholder="IPv4 or IPv6 prefix (required)"/>
          </div>
          <div class="span10">
            <input type="submit" class="btn primary" value="Add"/>
          </div>
        </fieldset>
      </form>
    </div>
    <div>
      <h2>Current filters</h2>{
        if (filters.entries.isEmpty)
          <div class="alert-message block-message"><p>No filters defined.</p></div>
        else {
          <table id="filters-table" class="zebra-striped" style="display: none;">
            <thead>
              <tr>
                <th>Prefix</th><th>Filtered ROA prefixes</th><th>&nbsp;</th>
              </tr>
            </thead>
            <tbody>{
              for (filter <- filters.entries) yield {
                val filteredOut = currentRtrPrefixes.filter(filter.shouldIgnore(_))
                def filteredOutDetails = {
                  <table>
                    <thead>
                      <tr><th>ASN</th><th>Prefix</th><th>Maximum Length</th></tr>
                    </thead>
                    {
                      for { rtrPrefix <- filteredOut } yield {
                        <tr>
                          <td> { rtrPrefix.asn.getValue.toString } </td>
                          <td> { rtrPrefix.prefix.toString } </td>
                          <td> { if (rtrPrefix.maxPrefixLength.isDefined) {
                                 rtrPrefix.maxPrefixLength.get.toString
                               } else {
                                 rtrPrefix.prefix.getPrefixLength.toString
                               } 
                          }
                          </td>
                        </tr>
                      }
                    }
                  </table>
                }

                <tr>
                  <td>{ filter.prefix }</td>
                  <td>
                    <span rel="popover" data-content={ Xhtml.toXhtml(filteredOutDetails) } data-original-title="Details">{ filteredOut.size + " prefix(es)" }</span>
                  </td>
                  <td>
                    <form method="POST" action="/filters" style="padding:0;margin:0;">
                      <input type="hidden" name="_method" value="DELETE"/>
                      <input type="hidden" name="prefix" value={ filter.prefix.toString }/>
                      <input type="submit" class="btn" value="delete"/>
                    </form>
                  </td>
                </tr>
              }
            }</tbody>
          </table>
          <script><!--
$(document).ready(function() {
  $('#filters-table').dataTable({
      "sPaginationType": "full_numbers",
      "aoColumns": [
        null, null,
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
