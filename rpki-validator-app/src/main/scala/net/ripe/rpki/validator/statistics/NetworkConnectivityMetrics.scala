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
package net.ripe.rpki.validator.statistics

import java.net._
import org.joda.time.DateTimeUtils
import org.apache.commons.io.IOUtils
import java.io.IOException

/**
 * Gather metrics on (rsync) certificate repository connectivity based on IPv4 and IPv6.
 */
class NetworkConnectivityMetrics(repositoryUri: URI) {
  private[this] val DEFAULT_RSYNC_PORT = 873

  val hostname = repositoryUri.getHost
  val port = if (repositoryUri.getPort == -1) DEFAULT_RSYNC_PORT else repositoryUri.getPort

  def metrics: Seq[Metric] = dnsMetrics ++ connectivityMetrics

  private[this] def dnsMetrics = Seq(
    Metric("network.connectivity[%s].ipv4" format hostname, addresses.exists(_.isInstanceOf[Inet4Address]).toString, DateTimeUtils.currentTimeMillis),
    Metric("network.connectivity[%s].ipv6" format hostname, addresses.exists(_.isInstanceOf[Inet6Address]).toString, DateTimeUtils.currentTimeMillis))

  private[this] def connectivityMetrics = addresses.flatMap { address =>
    val now = DateTimeUtils.currentTimeMillis
    val status = tryConnect(address)
    val elapsed = DateTimeUtils.currentTimeMillis - now
    Seq(
      Metric("network.connectivity[%s].status" format address, status, DateTimeUtils.currentTimeMillis),
      Metric("network.connectivity[%s].elapsed.ms" format address, elapsed.toString, DateTimeUtils.currentTimeMillis))
  }

  private[this] lazy val addresses = try InetAddress.getAllByName(hostname) catch {
    case e: UnknownHostException => Array.empty[InetAddress]
  }

  private[this] def tryConnect(address: InetAddress) = {
    val s = new Socket()
    try {
      s.setSoTimeout(5 * 60 * 1000)
      s.connect(new InetSocketAddress(address, port))
      "OK"
    } catch {
      case e: IOException => e.toString
    } finally {
      try s.close() catch { case _: IOException => }
    }
  }
}
