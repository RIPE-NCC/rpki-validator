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
package net.ripe.rpki.validator.views

import scala.xml._
import net.ripe.rpki.validator.rtr._

class RtrLogView extends View {

  def tab = Tabs.RoasTab
  def title = Text("Validated ROAs")
  def body = {
    <div class="alert-message block-message info">
      {
        <p>RPKI - RTR Activity log</p>
        <p>Log size: { RtrPduLog.pduLog.size } </p>

      }
    </div>
    <table id="log-table" class="zebra-striped" style="display: none;">
      <thead>
        <tr>
          <th>Time</th>
          <th>Sender</th>
          <th>Pdu Type</th>
          <th>Binary</th>
        </tr>
      </thead>
      <tbody>{
        for { entry <- RtrPduLog.pduLog } yield {
          <tr>
            <td>{ entry.time }</td>
            <td>{ entry.sender }</td>
            <td>{
              entry.data match {
                case Left(badData: BadData) => "Bad Data"
                case Right(pdu: Pdu) => pdu.pduType
                case _ => "Could not process input"
              }
            } </td>
            <td>{
              entry.data match {
                case Left(badData: BadData) => logBinaryContent(badData.content)
                case Right(pdu: Pdu) => logBinaryContent(Pdus.encode(pdu))
                case _ => "Could not process input"
              }
            }</td>
          </tr>
        }
      }</tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('#log-table').dataTable({
        "sPaginationType": "full_numbers"
    }).show();
});
// --></script>

  }

  def logBinaryContent(content: Array[Byte]) = {
    <pre> {
      var count = 0
      for { b <- content } yield {
        String.format("%02X", new java.lang.Byte(b)) + " "
      }
    }</pre>
  }

}