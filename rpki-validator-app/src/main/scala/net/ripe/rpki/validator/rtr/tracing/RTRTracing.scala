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
package net.ripe.rpki.validator.rtr.tracing

import grizzled.slf4j.Logger
import org.slf4j.MDC
import org.jboss.netty.channel.ChannelHandlerContext
import java.net.SocketAddress
import net.ripe.rpki.validator.rtr.{Pdu,BadData}
import java.lang.reflect.Field
import org.jboss.netty.buffer.ChannelBuffer

/**
 * Usable by components that want to log RTR protocol info to the rtr trace log
 */
trait RTRTracing {
  import TracingUtil._

  def traceOutgoingPdu(clientAddress: => Option[SocketAddress], pdu: Pdu) {
    PDUTracing.trace {
      "PDU OUT -> %s : %s { %s }".format(clientAddress.getOrElse("unknown client"), pdu.getClass().getName(), reflectionToString(pdu))
    }
  }
  
  def traceOutgoingPdus(clientAddress: => Option[SocketAddress], pdus: List[Pdu]) {
    if (PDUTracing.isEnabled)
      pdus.foreach(PDUTracing.trace(_))
  }
  
  def traceIncomingPdu(clientAddress: => Option[SocketAddress], incoming: Either[BadData, Pdu]) {
    PDUTracing.trace {
      " PDU IN <- %s : %s".format(clientAddress.getOrElse("unknown client"), 
      incoming match {
        case Left(BadData(errorCode, content)) => "BadData"
        case Right(pdu) => "%s { %s}".format(pdu.getClass().getSimpleName(), reflectionToString(pdu))
      })
    }
  }
  
  def traceIncomingData(clientAddress: => Option[SocketAddress], data: => Any) {
    DataTracing.trace {
      " BYTES IN <- %s : %s".format(clientAddress.getOrElse("unknown client"), hexDump(data))
    }
  }
  
  def traceOutgoingData(clientAddress: => Option[SocketAddress], data: Any) {
    DataTracing.trace {
      "BYTES OUT -> %s : %s".format(clientAddress.getOrElse("unknown client"), hexDump(data))
    }
  }
}

private[tracing] object TracingUtil {
  
  def reflectionToString(x: Any) = {
    x.getClass().getDeclaredFields().map(field => {
      field.setAccessible(true); formattedFieldWithValue(field, x)
    }).mkString(", ")
  }

  def formattedFieldWithValue(field:Field, instance:Any) = {
    val formattedValue = field.get(instance) match {
      case a: Array[_] =>  "["+ a.mkString(",") + "]"
      case a => a.toString()
    }
    field.getName() +"="+ formattedValue
  }
  
  def hexDump(data: Any) = {
    data match {
      case b: ChannelBuffer => b.array().map("0x%02x".format(_)).mkString(" ")
      case _ => "<unknown representation>"
    }
  }
}

private[tracing] class RTRTracingBase(loggerName:String, appenderName:String) {
  import org.apache.log4j.{Level, FileAppender, Logger=>Log4jLogger}
  
  val traceLog = {
    val logger = Logger(loggerName)
    if (logger.isTraceEnabled)
      classLog.info(tracingEnabledMessage)
    logger
  }
  val log4jTraceLogger = Log4jLogger.getLogger(loggerName)      // need to access log4j for changing level
  val classLog = Logger[this.type]

  private val tracingEnabledMessage = {
    "%s Tracing enabled - logging to %s".format(loggerName, log4jTraceLogger.getAppender(appenderName) match {
      case f: FileAppender => "file '%s'".format(f.getFile)
      case a => "log4j appender '%s'".format(a.getName)
    })
  }
  
  def isEnabled = traceLog.isTraceEnabled
  
  def enable() {
    log4jTraceLogger.setLevel(Level.TRACE)
    classLog.info(tracingEnabledMessage)
  }
  
  def disable() {
    log4jTraceLogger.setLevel(Level.OFF)
    classLog.info("RTR Tracing disabled")
  }
  
  def trace(msg: => Any) {
    traceLog.trace(msg)
  }
}

object PDUTracing extends RTRTracingBase("RTR_PDU", "RTR_APPENDER")
object DataTracing extends RTRTracingBase("RTR_DATA", "RTR_APPENDER")
