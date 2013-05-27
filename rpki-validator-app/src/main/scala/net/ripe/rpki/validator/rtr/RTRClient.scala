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
import org.jboss.netty.bootstrap.ClientBootstrap
import java.util.concurrent.Executors
import org.jboss.netty.channel._
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory
import java.net.InetSocketAddress
import grizzled.slf4j.Logger
import org.jboss.netty.handler.codec.frame.LengthFieldBasedFrameDecoder

class RTRClient(val port: Int) {

  val logger = Logger[this.type]

  @volatile
  var receivedPdus = List[Pdu]()

  val clientHandler = new RTRClientHandler(pduReceived)

  val bootstrap: ClientBootstrap = new ClientBootstrap(
    new NioClientSocketChannelFactory(
      Executors.newCachedThreadPool(),
      Executors.newCachedThreadPool()))

  bootstrap.setPipelineFactory(new ChannelPipelineFactory {
    override def getPipeline: ChannelPipeline = {
      Channels.pipeline(
        new LengthFieldBasedFrameDecoder(
          /*maxFrameLength*/ 65536,
          /*lengthFieldOffset*/ 4,
          /*lengthFieldLength*/ 4,
          /*lengthAdjustment*/ -8,
          /*initialBytesToStrip*/ 0),
        new PduDecoder,
        new PduEncoder,
        clientHandler)
    }
  })
  val channelFuture: ChannelFuture = bootstrap.connect(new InetSocketAddress("localhost", port))
  channelFuture.await(1000)

  def sendPdu(pduToSend: Pdu) { sendAny(pduToSend) }

  def sendData(data: Array[Byte]) { sendAny(data) }

  private def sendAny(data: Any) {
    channelFuture.getChannel.write(data)
    logger.trace("data sent")
  }

  def getResponse(expectedNumber: Int = 1, timeOut: Int = 1000): List[Pdu] = {
    var waited: Int = 0
    while(receivedPdus.size < expectedNumber && waited < timeOut) {
      Thread.sleep(5)
      waited += 5
    }
    val result = receivedPdus.take(expectedNumber)
    receivedPdus = receivedPdus.drop(expectedNumber)
    result
  }

  def getAllResponses: List[Pdu] = {
    val number = receivedPdus.length
    val result = receivedPdus.take(number)
    receivedPdus = receivedPdus.drop(number)
    result
  }

  def isConnected = {
    Thread.sleep(5) // make sure the RTR server gets some time to disconnect the client in tests.
    channelFuture.getChannel.isConnected
  }

  def pduReceived(pdu: Pdu) {
    logger.trace("Got back a PDU")
    receivedPdus = receivedPdus ++ List(pdu)
  }

  def close() {
    channelFuture.getChannel.close().await()
  }
}

class RTRClientHandler(pduReceived: Pdu => Unit) extends SimpleChannelUpstreamHandler {

  val logger = Logger[this.type]

  override def channelConnected(context: ChannelHandlerContext, event: ChannelStateEvent) {
    logger.trace("connected")
  }

  override def messageReceived(context: ChannelHandlerContext, event: MessageEvent) {
    logger.trace("Got response: " + event.getMessage)
    event.getMessage match {
      case Right(pdu: Pdu) =>
        pduReceived(pdu)
      case message =>
        logger.warn("bad message received: " + message)
    }
  }

  override def exceptionCaught(context: ChannelHandlerContext, event: ExceptionEvent) {
    // TODO: handle? Or just let it explode
    logger.error("Received exception: " + event.getCause.getMessage)
    logger.debug("", event.getCause)
  }

}