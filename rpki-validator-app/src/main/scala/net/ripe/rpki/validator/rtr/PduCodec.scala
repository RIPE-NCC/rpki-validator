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
package net.ripe.rpki.validator.rtr

import org.jboss.netty.channel._
import org.jboss.netty.handler.codec.frame.FrameDecoder
import org.jboss.netty.buffer.ChannelBuffer
import grizzled.slf4j.Logger
import org.jboss.netty.buffer.ChannelBuffers
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder

class PduDecoder extends FrameDecoder {
  val logger = Logger[this.type]
  val PduHeaderSize = 8

  object FieldOffset {
    val ProtocolVersion = 0
    val PduType = 1
    val ErrorCode = 2
    val Lenght = 4
    val Message = 8
  }
  
  override def decode(context:ChannelHandlerContext, channel:Channel, buffer:ChannelBuffer): Object = {
    if (buffer.readableBytes() < PduHeaderSize) {
      logger.trace("waiting for PDU header")
      null		// wait first for the header
    } else {
      val header = PduHeader(
          buffer.getByte(FieldOffset.ProtocolVersion),
          buffer.getByte(FieldOffset.PduType),
          buffer.getShort(FieldOffset.ErrorCode),
          buffer.getInt(FieldOffset.Lenght))
      logger.trace("PDU header received: pduType %d, errorCode=%d, lenght=%d".format(header.pduType, header.errorCode, header.length))
      if (buffer.readableBytes() < header.length) {
        logger.trace("waiting for PDU message")
        null	// wait for the rest of the frame
      } else {
        // TODO parsing to the correct PDU type
        val content = new Array[Byte](header.length)
        buffer.getBytes(FieldOffset.Message, content, 0, header.length - PduHeaderSize)
        buffer.skipBytes(header.length)
        
        UnknownPdu(header, content)
      }
    }
  }
}

class PduEncoder extends OneToOneEncoder {
  val logger = Logger[this.type]
  
  override def encode(context:ChannelHandlerContext, channel:Channel, msg:Object): Object = {
    val pdu = msg.asInstanceOf[Pdu]
    val buffer = ChannelBuffers.buffer(pdu.length)
    buffer.writeBytes(pdu.asByteArray)
    
    logger.trace("Response: written %d bytes".format(pdu.length))
    buffer
  }
}