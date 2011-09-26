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

import scala.collection.JavaConverters._
import scala.xml._
import models.Roas
import scalaz.concurrent.Promise
import net.ripe.commons.certification.cms.roa.RoaCms
import net.ripe.rpki.validator.models.TrustAnchor
import net.ripe.rpki.validator.models.ValidatedRoa

class RoasView(roas: Roas) extends View {
  def tab = RoasTab
  def title = Text("Validated ROAs")
  def body = {
    val (ready, loading) = roas.all.partition(_._2.fulfilled)
    <div class="alert-message block-message info">
      {
        optional(ready.nonEmpty, <p>Validated ROAs from { listTrustAnchorNames(ready.keys.toSeq) }.</p>) ++
          optional(loading.nonEmpty, <p>Still retrieving and validating ROAs from { listTrustAnchorNames(loading.keys.toSeq) }.</p>)
      }
      <div class="alert-actions">
        <a href="roas.csv" class="btn small">Download validated ROAs as CSV</a>
      </div>
    </div>
    <table id="roas-table" class="zebra-striped" style="display: none;">
      <thead>
        <th>ASN</th>
        <th>Prefix</th>
        <th>Maximum Length</th>
        <th>Trust Anchor</th>
      </thead>
      <tbody>{
        for {
          (trustAnchor, roas) <- ready
          validated <- roas.get
          roa = validated.roa
          prefix <- roa.getPrefixes().asScala
        } yield {
          <tr>
            <td>{ roa.getAsn().getValue() }</td>
            <td>{ prefix.getPrefix() }</td>
            <td>{ prefix.getEffectiveMaximumLength() } </td>
            <td>{ trustAnchor.name }</td>
          </tr>
        }
      }</tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('#roas-table').dataTable({
        "sPaginationType": "full_numbers"
    }).show();
});
// --></script>
  }

  private def optional(condition: Boolean, body: => NodeSeq) = if (condition) body else NodeSeq.Empty
  private def listTrustAnchorNames(elements: Seq[TrustAnchor]): NodeSeq =
    elements.map(_.name).sorted.map(name => <strong>{ name }</strong>: NodeSeq).reduce(_ ++ Text(", ") ++ _)
}
