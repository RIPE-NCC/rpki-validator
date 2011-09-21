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
package rtr

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.Charset


trait PduWriter {
  def asByteArray: Array[Byte]
}

abstract class Pdu extends PduWriter {
  final val protocolVersion: Byte = 0
  val pduType: Byte
  val length: Int
}

case class ErrorPdu(errorCode: Int, causingPdu: Option[Pdu] = None, errorText: Option[String] = None) extends Pdu {
  final override val pduType: Byte = 10

  val causingPduLength = causingPdu match {
    case Some(pdu) => pdu.length
    case None => 0
  }

  val errorTextLength = errorText match {
    case Some(text) => text.length()
    case None => 0
  }

  override val length = 8 + 4 + causingPduLength + 4 + errorTextLength
  
  override def asByteArray = {
    val bos = new ByteArrayOutputStream
    val data = new DataOutputStream(bos)

    // header
    data.writeByte(protocolVersion)
    data.writeByte(pduType)
    data.writeShort(errorCode)
    data.writeInt(length)

    // ErrorPdu specific content
    data.writeInt(causingPduLength)
    if (causingPdu != None) 
      data.write(causingPdu.get.asByteArray)
    data.writeInt(errorTextLength)
    if (errorText != None) 
      data.write(errorText.get.getBytes(Charset.forName("UTF-8")))

    data.flush()
    bos.toByteArray()
  }
  
}

object ErrorPdus {
  val NoDataAvailable = 2
}
