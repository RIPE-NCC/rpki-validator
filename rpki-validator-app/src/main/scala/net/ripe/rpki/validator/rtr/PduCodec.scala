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

import org.jboss.netty.channel._
import org.jboss.netty.buffer.ChannelBuffer
import grizzled.slf4j.Logger
import org.jboss.netty.buffer.ChannelBuffers
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder
import java.nio.ByteOrder


class PduDecoder extends OneToOneDecoder {
  val logger = Logger("RTR")

  override def decode(context: ChannelHandlerContext, channel: Channel, msg: Object): Object = {
    val buffer = msg.asInstanceOf[ChannelBuffer]

    val decoded = Pdus.fromByteArray(buffer)
    // Hardcoded to "client" for now -> quick and dirty logging to have a usable test server
    logger.debug(RtrPduLogEntry(channel.getRemoteAddress, decoded, Client))

    decoded
  }
}

class PduEncoder extends OneToOneEncoder {
  val logger = Logger("RTR")

  override def encode(context: ChannelHandlerContext, channel: Channel, msg: Object): Object = msg match {
    case responsePdus: Seq[_] =>
      val pdus = responsePdus.collect { case pdu: Pdu => pdu }

      val length = pdus.foldLeft(0) { _ + _.length }
      val buffer = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, length)

      for (pdu <- pdus) {
        buffer.writeBytes(Pdus.encode(pdu))

        // Hardcoded to "server" for now -> only the server sends lists of pdus
        logger.debug(RtrPduLogEntry(channel.getRemoteAddress, Right(pdu), Server))
      }
      buffer

    case pdu: Pdu =>
      val buffer = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, pdu.length)
      buffer.writeBytes(Pdus.encode(pdu))
      logger.debug(RtrPduLogEntry(channel.getRemoteAddress, Right(pdu), Server))
      buffer

    case bytes: Array[Byte] =>
      val buffer = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, bytes.length)
      buffer.writeBytes(bytes)
      buffer
  }
}

sealed trait Sender
case object Server extends Sender
case object Client extends Sender
