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
import org.jboss.netty.bootstrap.ClientBootstrap
import java.util.concurrent.Executors
import org.jboss.netty.channel._
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory
import java.net.InetSocketAddress
import grizzled.slf4j.Logger
import org.jboss.netty.buffer.ChannelBuffer
import org.jboss.netty.buffer.ChannelBuffers
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder
import org.jboss.netty.buffer.BigEndianHeapChannelBuffer

class RTRClient(val port: Int) {

  val logger = Logger[this.type]
  
  @volatile
  var receivedBytes: Option[Array[Byte]] = None
  
  val clientHandler = new RTRClientHandler(this)

  val bootstrap: ClientBootstrap = new ClientBootstrap(
    new NioClientSocketChannelFactory(
      Executors.newCachedThreadPool(),
      Executors.newCachedThreadPool()));

  bootstrap.setPipelineFactory(new ChannelPipelineFactory {
    override def getPipeline: ChannelPipeline = {
      Channels.pipeline(
        new LengthFieldBasedFrameDecoder(
          /*maxFrameLength*/ 4096,
          /*lengthFieldOffset*/ 4,
          /*lengthFieldLength*/ 4,
          /*lengthAdjustment*/ -8,
          /*initialBytesToStrip*/ 0),
        clientHandler)
    }
  })
  var channelFuture: ChannelFuture = bootstrap.connect(new InetSocketAddress("localhost", port))
  channelFuture.await(1000)

  def sendPdu(pduToSend: Pdu) = {
    
    receivedBytes = None
    
    var bytes = pduToSend.asByteArray;
    var buffer = ChannelBuffers.buffer(bytes.length)
    buffer.writeBytes(bytes)
    channelFuture.getChannel().write(buffer)
    logger.warn("pdu sent")
    
    while(!receivedBytes.isDefined) {
      Thread.sleep(5)
    }
    
    receivedBytes.get
  }

  def isConnected = {
    channelFuture.getChannel().isConnected()
  }

  def callBack(bytes: Array[Byte]) = {
    logger.warn("Got called back")
    receivedBytes = Some(bytes)
  }

  def close = {
    channelFuture.getChannel().close()
  }
}

class RTRClientHandler(val callingClient: RTRClient) extends SimpleChannelUpstreamHandler {

  val logger = Logger[this.type]

  override def channelConnected(context: ChannelHandlerContext, event: ChannelStateEvent) {
    logger.warn("connected")
  }

  override def messageReceived(context: ChannelHandlerContext, event: MessageEvent) {
    logger.warn("Got response: " + event.getMessage())
    var buffer: ChannelBuffer = event.getMessage.asInstanceOf[ChannelBuffer];
    callingClient.callBack(buffer.array())
  }

  override def exceptionCaught(context: ChannelHandlerContext, event: ExceptionEvent) {
    // TODO maybe send 'no data available' PDU
    logger.warn("Received exception: " + event.getCause().getMessage())
  }

}