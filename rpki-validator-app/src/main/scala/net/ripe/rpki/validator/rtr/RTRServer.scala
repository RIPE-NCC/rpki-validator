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
import scala.collection.JavaConverters._
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.net.InetSocketAddress
import org.jboss.netty.buffer.ChannelBuffer
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder
import org.jboss.netty.handler.codec.frame.CorruptedFrameException
import org.jboss.netty.handler.codec.frame.TooLongFrameException
import org.jboss.netty.handler.timeout.ReadTimeoutException
import org.jboss.netty.channel._
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory
import org.jboss.netty.handler.timeout.ReadTimeoutHandler
import org.jboss.netty.util.Timer
import org.jboss.netty.util.HashedWheelTimer
import grizzled.slf4j.Logger
import org.slf4j.MDC
import net.ripe.rpki.validator.models.Roas
import net.ripe.rpki.validator.config.Database
import net.ripe.rpki.validator.config.UpdateListener
import net.ripe.ipresource.IpResourceType
import net.ripe.ipresource.Ipv4Address
import net.ripe.ipresource.Ipv6Address

object RTRServer {
  final val ProtocolVersion = 0
  final val MAXIMUM_FRAME_LENGTH = 16777216 // 16MB Note: this should be big enough to contain all pdus when we respond with data 
}

class RTRServer(port: Int, getCurrentCacheSerial: () => Int, getCurrentRoas: () => Roas, getCurrentNonce: () => Int) extends UpdateListener {
  import TimeUnit._

  val logger = Logger[this.type]

  var bootstrap: ServerBootstrap = _
  var timer: Timer = new HashedWheelTimer(5, SECONDS) // check for timer events every 5 secs

  val serverHandler = new RTRServerHandler(getCurrentCacheSerial, getCurrentRoas, getCurrentNonce)

  def notify(serial: Long) = {
    logger.info("Got an update")
    serverHandler.notifyChildren(serial)
  }

  def startServer(): Unit = {

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
    logger.trace("RTR tracing enabled")
  }

  def registerShutdownHook() {
    sys.addShutdownHook({
      stopServer()
      logger.info("RTR server stopped")
    })
  }

  def stopServer() {
    // TODO graceful: close all open channels asynchronously
    bootstrap.getFactory().releaseExternalResources()
  }
}

class RTRServerHandler(getCurrentCacheSerial: () => Int, getCurrentRoas: () => Roas, getCurrentNonce: () => Int) extends SimpleChannelUpstreamHandler {

  import scala.collection.mutable.HashMap
  import java.net.SocketAddress

  val logger = Logger[this.type]

  @volatile //?
  var childChannelMap = new HashMap[SocketAddress, Channel]

  override def channelConnected(context: ChannelHandlerContext, event: ChannelStateEvent) {
    MDC.put("contextName", context.getName())
    MDC.put("clientAddress", event.getChannel().getRemoteAddress().toString())

    var childChannel = event.getChannel()
    childChannelMap.put(childChannel.getRemoteAddress(), childChannel)

    super.channelConnected(context, event)
  }

  def notifyChildren(serial: Long) = {
    childChannelMap.values.foreach {
      channel =>
        if (channel.isOpen()) {
          channel.write(new SerialNotifyPdu(nonce = getCurrentNonce.apply(), serial = getCurrentCacheSerial.apply()))
        }
    }
  }

  override def channelClosed(context: ChannelHandlerContext, event: ChannelStateEvent) {
    super.channelClosed(context, event)
    MDC.remove("contextName")
    MDC.remove("clientAddress")

    var childChannel = event.getChannel()
    childChannelMap.remove(childChannel.getRemoteAddress())
  }

  override def messageReceived(context: ChannelHandlerContext, event: MessageEvent) {
    import org.jboss.netty.buffer.ChannelBuffers

    if (logger.isTraceEnabled) {
      val clientAddr = event.getRemoteAddress().asInstanceOf[InetSocketAddress]
      logger.trace("RTR request received from " + clientAddr.getAddress.toString)
    }

    // decode and process
    val requestPdu = event.getMessage().asInstanceOf[Either[BadData, Pdu]]
    var responsePdus: List[Pdu] = processRequest(requestPdu)

    // respond
    val channelFuture = event.getChannel().write(responsePdus)

    responsePdus.last match {
      case ErrorPdu(errorCode, _, _) if (ErrorPdu.isFatal(errorCode)) =>
        channelFuture.addListener(ChannelFutureListener.CLOSE)
      case _ =>
    }

  }

  private def processRequest(request: Either[BadData, Pdu]): List[Pdu] = {
    request match {
      case Left(BadData(errorCode, content)) => List(ErrorPdu(errorCode, content, ""))
      case Right(ResetQueryPdu()) => processResetQuery
      case Right(SerialQueryPdu(nonce, serial)) => processSerialQuery(nonce, serial)
      case Right(_) => List(ErrorPdu(ErrorPdu.InvalidRequest, Array.empty, ""))
    }
  }

  override def exceptionCaught(context: ChannelHandlerContext, event: ExceptionEvent) {
    // Can anyone think of a nice way to test this? Without tons of mocking and overkill?
    // Otherwise I will assume the code below is doing too little to be able to contain bugs ;)
    logger.warn("Exception: " + event.getCause, event.getCause)

    if (event.getChannel().isOpen()) {
      val response: Pdu = event.getCause() match {
        case cause: CorruptedFrameException => ErrorPdu(ErrorPdu.CorruptData, Array.empty, cause.toString())
        case cause: TooLongFrameException => ErrorPdu(ErrorPdu.CorruptData, Array.empty, cause.toString())
        case cause: ReadTimeoutException => ErrorPdu(ErrorPdu.InternalError, Array.empty, "Connection timed out")
        case cause => ErrorPdu(ErrorPdu.InternalError, Array.empty, cause.toString())
      }

      val channelFuture = event.getChannel().write(response)
      channelFuture.addListener(ChannelFutureListener.CLOSE)
    }
  }

  private def processResetQuery: List[Pdu] = {
    getCurrentCacheSerial.apply() match {
      case 0 => List(ErrorPdu(ErrorPdu.NoDataAvailable, Array.empty, ""))
      case _ =>
        var responsePdus: List[Pdu] = List[Pdu]()
        responsePdus = responsePdus ++ List(CacheResponsePdu(nonce = getCurrentNonce.apply()))
        for {
          (_, validatedRoas) <- getCurrentRoas.apply().all if validatedRoas.isDefined
          validatedRoa <- validatedRoas.get.sortBy(_.roa.getAsn().getValue())
          roa = validatedRoa.roa
          prefix <- roa.getPrefixes().asScala
        } {
          var maxLength = prefix.getEffectiveMaximumLength()
          var length = prefix.getPrefix().getPrefixLength()

          prefix.getPrefix().getStart() match {
            case ipv4: Ipv4Address => 
              responsePdus = responsePdus ++ List(IPv4PrefixAnnouncePdu(ipv4, length.toByte, maxLength.toByte, roa.getAsn()))
            case ipv6: Ipv6Address =>
              responsePdus = responsePdus ++ List(IPv6PrefixAnnouncePdu(ipv6, length.toByte, maxLength.toByte, roa.getAsn()))
            case _ => assert(false)
          }
          logger.info("Prefix: " + prefix)
        }
        responsePdus ++ List(EndOfDataPdu(nonce = getCurrentNonce.apply(), serial = getCurrentCacheSerial.apply()))
    }
  }

  private def processSerialQuery(nonce: Int, serial: Long) = {
    if (nonce == getCurrentNonce.apply() && serial == getCurrentCacheSerial.apply()) {
      List(ErrorPdu(ErrorPdu.NoDataAvailable, Array.empty, ""))
    } else {
      List(CacheResetPdu())
    }
  }
}