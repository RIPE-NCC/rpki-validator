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

import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import java.net.URI

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class NetworkConnectivityMetricsTest extends FunSuite with ShouldMatchers {
  test("should check IPv4 connectivity") {
    val metrics = new NetworkConnectivityMetrics(URI.create("rsync://127.0.0.1/")).metrics.map(x => (x.name, x.value)).toMap

    metrics should contain("network.connectivity[127.0.0.1].ipv4.count" -> "1")
    metrics should contain("network.connectivity[127.0.0.1].ipv6.count" -> "0")
    metrics should contain key("network.connectivity[/127.0.0.1].status")
    metrics should contain key("network.connectivity[/127.0.0.1].elapsed.ms")
  }

  test("should check IPv6 connectivity") {
    val metrics = new NetworkConnectivityMetrics(URI.create("rsync://[::1]/")).metrics.map(x => (x.name, x.value)).toMap

    metrics should contain("network.connectivity[[::1]].ipv4.count" -> "0")
    metrics should contain("network.connectivity[[::1]].ipv6.count" -> "1")
    metrics should contain key("network.connectivity[/0:0:0:0:0:0:0:1].status")
    metrics should contain key("network.connectivity[/0:0:0:0:0:0:0:1].elapsed.ms")
  }
}
