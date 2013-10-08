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
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

class RtrSessionsView(sessions: Iterable[RtrSessionData], now: DateTime = new DateTime) extends View with ViewHelpers {

  def tab = Tabs.RtrSessionsTab
  def title = Text("Router Sessions")

  def body = {
    <p>
      This table shows all routers connected to this RPKI Validator. Requests and responses are described in <a href="http://tools.ietf.org/html/rfc6810">RFC 6810</a>. For debugging, please refer to rtr.log.
    </p>

    <table class="zebra-striped">
      <thead>
        <tr>
          <th>Remote Address</th>
          <th>Connection Time</th>
          <th>Last Request Time</th>
          <th>Last Request</th>
          <th>Last Reply</th>
        </tr>
      </thead>
      <tbody>{
        if (sessions.isEmpty)
          <tr><td colspan="5"><span class="label">No connections</span></td></tr>
        else
          for (sessionData <- sessions.iterator if sessionData.connected.value) yield {
            <tr>
              <td>{sessionData.remoteAddr.toString.replaceFirst("^/","")}</td>
              <td>{formatConnectionTime(sessionData)}</td>
              <td>{formatLastRequestTime(sessionData)}</td>
              <td>{formatPduReceived(sessionData)}</td>
              <td>{formatPduSent(sessionData)}</td>
            </tr>
          }
        }</tbody>
    </table>
  }

  def formatConnectionTime(sessionData: RtrSessionData): NodeSeq = {
    <span>{sessionData.connected.time.toString(timeFormatter)}</span>
  }

  def formatLastRequestTime(sessionData: RtrSessionData): NodeSeq = {
    <span>{sessionData.lastPduReceived.get.time.toString(timeFormatter)}</span>
  }

  def formatPduReceived(sessionData: RtrSessionData): NodeSeq = {
    if (sessionData.lastPduReceived.isDefined) {
      <span>{sessionData.lastPduReceived.get.value}</span>
    } else {
      NodeSeq.Empty
    }
  }

  def formatPduSent(sessionData: RtrSessionData): NodeSeq = {
    if (sessionData.lastPduSent.isDefined) {
      <span>{sessionData.lastPduSent.get.value.getClass.getSimpleName}</span>
    } else {
      NodeSeq.Empty
    }
  }

  val timeFormatter = ISODateTimeFormat.dateTimeNoMillis()
}
