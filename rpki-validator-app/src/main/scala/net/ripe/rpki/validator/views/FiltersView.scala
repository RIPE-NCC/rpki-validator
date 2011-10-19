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

import scalaz._
import Scalaz._
import scala.xml._
import net.ripe.rpki.validator.rtr._
import models._
import scalaz.NonEmptyList
import net.ripe.rpki.validator.lib.Validation.ErrorMessage

class FiltersView(filters: Filters, params: Map[String, String] = Map.empty, errors: Seq[ErrorMessage] = Seq.empty) extends View {
  private val fieldNameToText = Map("prefix" -> "Prefix")

  def tab = Tabs.FiltersTab
  def title = Text(tab.text)
  def body = {
    <div>
      <h2>Add filter</h2>
      <p>By adding a filter the validator will ignore any RPKI prefixes that overlap with the filter's prefix.</p>
    </div>
    <div>{
      if (errors.nonEmpty) {
        <div class="alert-message block-message error">
          <strong>Please fix the following errors and resubmit the form</strong>
          <ul>
            {
              for (error <- errors) yield <li>{ error.fieldName.map(name => fieldNameToText(name) + ": ").getOrElse("") + error.message }</li>
            }
          </ul>
        </div>
      }
    }</div>
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
      <h2>Current entries</h2><br/>{
        if (filters.entries.isEmpty)
          <div class="alert-message block-message"><p>No filters defined.</p></div>
        else {
          <table id="filters-table" class="zebra-striped" style="display: none;">
            <thead>
              <tr>
                <th>Prefix</th><th>&nbsp;</th>
              </tr>
            </thead>
            <tbody>{
              for (entry <- filters.entries) yield {
                <tr>
                  <td>{ entry.prefix }</td>
                  <td>
                    <form method="POST" action="/filters" style="padding:0;margin:0;">
                      <input type="hidden" name="_method" value="DELETE"/>
                      <input type="hidden" name="prefix" value={ entry.prefix.toString }/>
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
        null,
        { "bSortable": false }
      ]
    }).show();
});
// --></script>
        }
      }
    </div>
  }
}
