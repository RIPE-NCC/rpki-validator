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
package net.ripe.rpki.validator.rtr

import net.ripe.rpki.validator.models.RtrPrefix
import java.lang.Throwable
import scala.collection.mutable


class RtrSessions[T](getCurrentCacheSerial: () => Int,
                     getCurrentRtrPrefixes: () => Seq[RtrPrefix],
                     getCurrentSessionId: () => Pdu.SessionId,
                     hasTrustAnchorsEnabled: () => Boolean) {

  private val handlers = mutable.HashMap[T, RtrSessionHandler[T]]()

  def allClientData = handlers.values.map(_.sessionData)

  def connect(id: T) {
    val handler = handlers.getOrElseUpdate(id, new RtrSessionHandler[T](id,
      getCurrentCacheSerial, getCurrentRtrPrefixes, getCurrentSessionId, hasTrustAnchorsEnabled))
    handler.connect()
  }

  def disconnect(id: T) = handlers.remove(id).foreach(_.disconnect())

  def serialNotify(serial: Long) = {
    val pdu = new SerialNotifyPdu(getCurrentSessionId(), serial)
    handlers.values.foreach(_.serialNotify(pdu))
    pdu
  }

  def responseForRequest(id: T, request: Either[BadData, Pdu]) = {
    handlerFor(id).processRequest(request)
  }

  def determineErrorPdu(id: T, cause: Throwable): Pdu = {
    handlerFor(id).determineErrorPdu(cause)
  }

  private def handlerFor(id: T) = handlers.get(id).get
}
