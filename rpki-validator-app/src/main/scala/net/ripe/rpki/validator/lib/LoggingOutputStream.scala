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
package net.ripe.rpki.validator.lib

import java.io.{IOException, OutputStream}

import grizzled.slf4j.Logging


class LoggingOutputStream extends OutputStream with Logging {
  protected val LINE_SEPARATOR: String = System.getProperty("line.separator")
  protected var hasBeenClosed: Boolean = false
  protected var buf: Array[Byte] = null
  protected var count: Int = 0
  private var bufLength: Int = 0
  val DEFAULT_BUFFER_LENGTH: Int = 2048

  bufLength = DEFAULT_BUFFER_LENGTH
  buf = new Array[Byte](DEFAULT_BUFFER_LENGTH)
  count = 0

  override def close() {
    flush()
    hasBeenClosed = true
  }

  @throws(classOf[IOException])
  def write(b: Int) {
    if (hasBeenClosed) {
      throw new IOException("The stream has been closed.")
    }
    if (b == 0) {
      return
    }
    if (count == bufLength) {
      val newBufLength: Int = bufLength + DEFAULT_BUFFER_LENGTH
      val newBuf: Array[Byte] = new Array[Byte](newBufLength)
      System.arraycopy(buf, 0, newBuf, 0, bufLength)
      buf = newBuf
      bufLength = newBufLength
    }
    buf(count) = b.toByte
    count += 1
  }

  override def flush() {
    if (count == 0) {
      return
    }
    if (count == LINE_SEPARATOR.length) {
      if (buf(0).toChar == LINE_SEPARATOR.charAt(0)
          && ((count == 1) || ((count == 2) && buf(1).toChar == LINE_SEPARATOR.charAt(1)))) {
        reset()
        return
      }
    }
    val theBytes: Array[Byte] = new Array[Byte](count)
    System.arraycopy(buf, 0, theBytes, 0, count)
    logger.warn(new String(theBytes))
    reset()
  }

  private def reset() {
    count = 0
  }
}
