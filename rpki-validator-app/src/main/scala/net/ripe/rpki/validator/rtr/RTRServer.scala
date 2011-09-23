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

import org.jboss.netty.bootstrap.ServerBootstrap
import java.util.concurrent.Executors
import org.jboss.netty.channel._
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory
import java.net.InetSocketAddress
import grizzled.slf4j.Logger
import org.jboss.netty.buffer.ChannelBuffer
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder
import org.jboss.netty.handler.codec.frame.CorruptedFrameException

object RTRServer {
  final val ProtocolVersion = 0
  val Port = 8282

  val logger = Logger[this.type]

  var bootstrap: ServerBootstrap = _

  def startServer(): Unit = {
    bootstrap = new ServerBootstrap(new NioServerSocketChannelFactory(
      Executors.newCachedThreadPool(),
      Executors.newCachedThreadPool()))

    registerShutdownHook()

    bootstrap.setPipelineFactory(new ChannelPipelineFactory {
      override def getPipeline: ChannelPipeline = {
        Channels.pipeline(
          new LengthFieldBasedFrameDecoder(
            /*maxFrameLength*/ 4096,
            /*lengthFieldOffset*/ 4,
            /*lengthFieldLength*/ 4,
            /*lengthAdjustment*/ -8,
            /*initialBytesToStrip*/ 0),
          new PduEncoder,
          new PduDecoder,
          new RTRServerHandler)
      }
    })
    bootstrap.setOption("child.keepAlive", true)
    val listenAddress = new InetSocketAddress(Port)
    bootstrap.bind(listenAddress)

    logger.info("RTR server listening on " + listenAddress.toString)
    logger.trace("RTR tracing enabled")
  }

  def registerShutdownHook() {
    Runtime.getRuntime.addShutdownHook(new Thread {
      override def run() {
        stopServer()
        logger.info("RTR server stopped")
      }
    })
  }

  def stopServer() {
    // TODO graceful: close all open channels asynchronously
    bootstrap.getFactory().releaseExternalResources()
  }
}

class RTRServerHandler extends SimpleChannelUpstreamHandler {

  val logger = Logger[this.type]

  override def messageReceived(context: ChannelHandlerContext, event: MessageEvent) {
    import org.jboss.netty.buffer.ChannelBuffers

    if (logger.isTraceEnabled) {
      val clientAddr = event.getRemoteAddress().asInstanceOf[InetSocketAddress]
      logger.trace("RTR request received from " + clientAddr.getAddress.toString)
    }

    // decode and process
    val requestPdu: Pdu = event.getMessage().asInstanceOf[Pdu]
    var responsePdu: Pdu = processRequest(requestPdu)

    // respond
    event.getChannel().write(responsePdu)
  }

  private def processRequest(requestPdu: Pdu) = {
    requestPdu match {
      case requestPdu: ResetQueryPdu => new ErrorPdu(ErrorPdus.NoDataAvailable, None, None)
      case requestPdu: UnknownPdu => new ErrorPdu(ErrorPdus.UnsupportedPduType, None, None)
      case requestPdu: UnsupportedProtocolPdu => new ErrorPdu(ErrorPdus.UnsupportedProtocolVersion, None, None)
      case _ => new ErrorPdu(ErrorPdus.InvalidRequest, None, None)
    }
  }

  override def exceptionCaught(context: ChannelHandlerContext, event: ExceptionEvent) {
    // Can anyone think of a nice way to test this? Without tons of mocking and overkill?
    // Otherwise I will assume the code below is doing too little to be able to contain bugs ;)
    logger.warn("Exception: " + event.getCause().getMessage())
    logger.debug("", event.getCause())

    var errorPdu: Pdu = null
    val cause = event.getCause() match {
      case cause: CorruptedFrameException => errorPdu = new ErrorPdu(ErrorPdus.CorruptData, None, None)
      case _ => errorPdu = new ErrorPdu(ErrorPdus.InternalError, None, None)
    }

    event.getChannel().write(errorPdu)
  }
}