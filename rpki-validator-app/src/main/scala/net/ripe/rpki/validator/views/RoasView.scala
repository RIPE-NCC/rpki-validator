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
import models.ValidatedObjects
import net.ripe.rpki.validator.util.TrustAnchorLocator

class RoasView(validatedObjects: ValidatedObjects, search: String) extends View {
  def tab = Tabs.RoasTab
  def title = Text("Validated ROAs")
  def body = {
    val (loading, ready) = validatedObjects.all.partition(_._2.validatedObjects.isEmpty)
    <div class="alert-message block-message info" data-alert="alert">
    <a class="close" href="#">×</a>
      {
        optional(ready.nonEmpty, <p>Validated ROAs from { listTrustAnchorNames(ready.keys.toSeq) }.</p>) ++
        optional(loading.nonEmpty, <p>Still retrieving and validating ROAs from { listTrustAnchorNames(loading.keys.toSeq) }.</p>)
      }
    </div>
    <table id="roas-table" class="zebra-striped" style="display: none;" data-search={ search }>
      <thead>
        <tr>
          <th>ASN</th>
          <th>Prefix</th>
          <th>Maximum Length</th>
          <th>Trust Anchor</th>
        </tr>
      </thead>
      <tbody>
      </tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('#roas-table').dataTable({
        "oSearch": {"sSearch": $('#roas-table').attr('data-search')},
        "sPaginationType": "full_numbers",
        "bProcessing": true,
        "bServerSide": true,
        "sAjaxSource": "roas-data"
    }).show();
});
// --></script>
  }

  private def optional(condition: Boolean, body: => NodeSeq) = if (condition) body else NodeSeq.Empty
  private def listTrustAnchorNames(elements: Seq[TrustAnchorLocator]): NodeSeq =
    elements.map(_.getCaName).sorted.map(name => <strong>{ name }</strong>: NodeSeq).reduce(_ ++ Text(", ") ++ _)
}
