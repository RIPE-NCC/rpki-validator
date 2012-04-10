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

import rtr.RtrSessionData
import lib.DateAndTime._
import Tabs._
import org.joda.time.{DateTime, Period}
import org.joda.time.format.ISODateTimeFormat

class RtrSessionsView(sessions: Iterable[RtrSessionData], now: DateTime = new DateTime) extends View with ViewHelpers {

  def tab = Tabs.RtrSessionsTab
  def title = Text("Router Sessions")

  def body = {
    <p>
	  See below for a list routers that have connected to this validator.
      See <a href={ RtrLogTab.url }>here</a> for debug logging of these connections. 
	</p>
    
    <table class="zebra-striped">
      <thead>
        <tr>
          <th>Remote Address</th>
          <th>State</th>
          <th>Last Request from Client</th>
          <th>Last Serial Sent</th>
        </tr>
      </thead>
      <tbody>{
        if (sessions.isEmpty)
          <tr><td colspan="4"><span class="label">No connections</span></td></tr>
        else
          for (sessionData <- sessions.iterator) yield {
            <tr>
              <td>{sessionData.remoteAddr.toString.replaceFirst("^/","")}</td>
              <td>{formatConnectionState(sessionData)}</td>
              <td>{formatPduReceived(sessionData)}</td>
              <td>{formatPduSent(sessionData)}</td>
            </tr>
          }
        }</tbody>
    </table>
    <script><!--
$(document).ready(function() {
  $('[rel=twipsy]').twipsy({
    "live": true
  });
});
// --></script>

  }

  def formatConnectionState(sessionData: RtrSessionData): NodeSeq = {
    val connected = sessionData.connected.value
    val labelClass = if (connected) "label success" else "label"
    val stateText = if (connected) "Connected" else "Disconnected"
    val timeText = sessionData.connected.time.toString(timeFormatter)
    val periodText = periodInWords(new Period(sessionData.connected.time, now)) + " ago"

    <span rel="twipsy" data-original-title={periodText}>{timeText} </span>
    <span class={labelClass}>{stateText}</span>
  }

  def formatPduReceived(sessionData: RtrSessionData): NodeSeq = {
    if (sessionData.lastPduReceived.isDefined) {
      val pduName = sessionData.lastPduReceived.get.value
      val timeText = sessionData.lastPduReceived.get.time.toString(timeFormatter)
      val periodText = periodInWords(new Period(sessionData.connected.time, now)) + " ago"

      <span rel="twipsy" data-original-title={periodText}>{timeText} </span>
      <strong>{pduName}</strong>
    } else {
      NodeSeq.Empty
    }
  }

  def formatPduSent(sessionData: RtrSessionData): NodeSeq = {
    if (sessionData.lastPduSent.isDefined) {
      val pduName = sessionData.lastPduSent.get.value.getClass.getSimpleName
      val pduDetails = sessionData.lastPduSent.get.value.toPrettyContentString()
      val timeText = sessionData.lastPduSent.get.time.toString(timeFormatter)
      val periodText = periodInWords(new Period(sessionData.connected.time, now)) + " ago"

      <span rel="twipsy" data-original-title={periodText}>{timeText} </span>
      <strong rel="twipsy" data-original-title={pduDetails}>{pduName}</strong>
    } else {
      NodeSeq.Empty
    }
  }

  val timeFormatter = ISODateTimeFormat.time()
}
