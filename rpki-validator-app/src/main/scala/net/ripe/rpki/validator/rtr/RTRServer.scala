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
package rtr

import java.net.{InetSocketAddress, SocketAddress}
import java.util.concurrent.{Executors, TimeUnit}

import grizzled.slf4j.{Logger, Logging}
import net.ripe.rpki.validator.models.RtrPrefix
import org.jboss.netty.bootstrap.ServerBootstrap
import org.jboss.netty.channel.ChannelHandler.Sharable
import org.jboss.netty.channel._
import org.jboss.netty.channel.group.{ChannelGroup, DefaultChannelGroup}
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder
import org.jboss.netty.handler.timeout.ReadTimeoutHandler
import org.jboss.netty.util.{HashedWheelTimer, Timer}


object RTRServer {
  final val ProtocolVersion = 0
  final val MAXIMUM_FRAME_LENGTH = 16777216 // 16MB Note: this should be big enough to contain all pdus when we respond with data

  val allChannels: ChannelGroup = new DefaultChannelGroup("rtr-server")
}

class RTRServer(port: Int, closeOnError: Boolean, sendNotify: Boolean,
                getCurrentCacheSerial: () => Int,
                getCurrentRtrPrefixes: () => Seq[RtrPrefix],
                getCurrentSessionId: () => Pdu.SessionId,
                hasTrustAnchorsEnabled: () => Boolean)
  extends Logging {

  import TimeUnit._

  var bootstrap: ServerBootstrap = _
  var timer: Timer = new HashedWheelTimer(5, SECONDS) // check for timer events every 5 secs

  val rtrSessions = new RtrSessions[SocketAddress](getCurrentCacheSerial, getCurrentRtrPrefixes, getCurrentSessionId, hasTrustAnchorsEnabled)

  val serverHandler = new RTRServerHandler(closeOnError, rtrSessions)

  def notify(serial: Long) = {
    if (sendNotify) {
      info("Sending Notify with serial %s to all clients".format(serial))
      serverHandler.notifyChildren(rtrSessions.serialNotify(serial))
    }
  }

  def startServer() {

    bootstrap = new ServerBootstrap(new NioServerSocketChannelFactory(
      Executors.newCachedThreadPool(),
      Executors.newCachedThreadPool()))

    registerShutdownHook()

    bootstrap.setPipelineFactory(new ChannelPipelineFactory {
      override def getPipeline: ChannelPipeline = {
        Channels.pipeline(
          new ReadTimeoutHandler(timer, 1, HOURS),
          new LengthFieldBasedFrameDecoder(
            /*maxFrameLength*/ RTRServer.MAXIMUM_FRAME_LENGTH,
            /*lengthFieldOffset*/ 4,
            /*lengthFieldLength*/ 4,
            /*lengthAdjustment*/ -8,
            /*initialBytesToStrip*/ 0),
          new PduEncoder,
          new PduDecoder,
          serverHandler)
      }
    })
    bootstrap.setOption("child.keepAlive", true)
    val listenAddress = new InetSocketAddress(port)
    bootstrap.bind(listenAddress)

    logger.info("RTR server listening on " + listenAddress.toString)
  }

  def registerShutdownHook() {
    sys.addShutdownHook({
      stopServer()
      logger.info("RTR server stopped")
    })
  }

  def stopServer() {
    val futureClose = RTRServer.allChannels.close()
    futureClose.await(30, SECONDS)
    bootstrap.getFactory.releaseExternalResources()
  }
}

@Sharable
class RTRServerHandler(closeOnError: Boolean = true, clients: RtrSessions[SocketAddress])
  extends SimpleChannelUpstreamHandler with Logging {

  val rtrLogger = Logger("RTR")

  override def channelOpen(context: ChannelHandlerContext, event: ChannelStateEvent) {
    RTRServer.allChannels.add(event.getChannel) // will be removed automatically on close
    val remoteAddress: SocketAddress = context.getChannel.getRemoteAddress
    clients.connect(remoteAddress)
    info("Client connected : " + remoteAddress)
    rtrLogger.info("Client connected : " + remoteAddress) // log to both, interesting in general, but also needed in debugging
  }

  override def channelDisconnected(context: ChannelHandlerContext, event: ChannelStateEvent) {
    super.channelDisconnected(context, event)
    val socketAddress = context.getChannel.getRemoteAddress
    clients.disconnect(socketAddress)
    info("Client disconnected : " + socketAddress)
    rtrLogger.info("Client disconnected : " + socketAddress) // log to both, interesting in general, but also needed in debugging
  }

  def notifyChildren(pdu: Pdu) = RTRServer.allChannels.write(pdu)

  override def messageReceived(context: ChannelHandlerContext, event: MessageEvent) {
    val clientAddress = context.getChannel.getRemoteAddress

    // decode and process
    val requestPdu = event.getMessage.asInstanceOf[Either[BadData, Pdu]]
    val responsePdus: Seq[Pdu] = clients.responseForRequest(clientAddress, requestPdu)

    // respond
    val channelFuture = event.getChannel.write(responsePdus)

    if (closeOnError) {
      responsePdus.last match {
        case ErrorPdu(errorCode, _, _) if ErrorPdu.isFatal(errorCode) =>
          channelFuture.addListener(ChannelFutureListener.CLOSE)
        case _ =>
      }
    }
  }

  override def exceptionCaught(context: ChannelHandlerContext, event: ExceptionEvent) {
    // Can anyone think of a nice way to test this? Without tons of mocking and overkill?
    // Otherwise I will assume the code below is doing too little to be able to contain bugs ;)
    logger.warn(event.getCause)

    if (event.getChannel.isOpen) {
      val response: Pdu = clients.determineErrorPdu(context.getChannel.getRemoteAddress, event.getCause)

      try {
        val channelFuture = event.getChannel.write(response)
        channelFuture.addListener(ChannelFutureListener.CLOSE)
      } catch {
        case _: Exception => event.getChannel.close()
      }
    }
  }

}
