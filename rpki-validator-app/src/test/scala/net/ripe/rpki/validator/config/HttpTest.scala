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
package net.ripe.rpki.validator.config

import java.io.File
import java.security.KeyStore

import grizzled.slf4j.Logging
import net.ripe.rpki.validator.support.{JunitLog4JSetup, ValidatorTestCase}
import org.apache.http.client.methods.{CloseableHttpResponse, HttpGet}
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.server._
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.scalatest.BeforeAndAfterAll

import scala.util.Try

class HttpTest extends ValidatorTestCase with JunitLog4JSetup with BeforeAndAfterAll {

  override def beforeAll() {
    HttpServer.start()
  }

  override def afterAll() {
    HttpServer.stop()
  }

  val subject = new Http with Logging {
    override def trustedCertsLocation: File = new File("/Users/oleg/dev/checkouts/rpki/rpki-validator/rpki-validator-app/src/test/resources/trusted.ssl.certs")
  }

  test("Should connect to http server") {
    HttpServer.httpPort

    val response: CloseableHttpResponse = subject.http.execute(new HttpGet(s"http://localhost:${HttpServer.httpPort}"))
    Try {
      response.getStatusLine.getStatusCode
    } should be a 'Success

    response.close()
  }

  test("Should connect to https server") {
    val response: CloseableHttpResponse = subject.http.execute(new HttpGet(s"https://localhost:${HttpServer.httpsPort}"))
    Try {
      response.getStatusLine.getStatusCode
    } should be a 'Success

    response.close()
  }


  object HttpServer {
    import org.eclipse.jetty.server.Server
    val server = new Server()

    val http_config = new HttpConfiguration()
    http_config.setSecureScheme("https")
    val http = new ServerConnector(server, new HttpConnectionFactory(http_config))
    http.setPort(0)
//    http.setIdleTimeout(30000)
    server.addConnector(http)

    private val customKeyStore = KeyStore.getInstance("jceks")
    customKeyStore.load(getClass.getResourceAsStream("/jetty.test.keystore"), "jetty.keystore".toCharArray)

    val sslContextFactory = new SslContextFactory()
    sslContextFactory.setKeyStore(customKeyStore)
    sslContextFactory.setKeyManagerPassword("jetty")

    val https_config = new HttpConfiguration(http_config)
    https_config.addCustomizer(new SecureRequestCustomizer())

    val https = new ServerConnector(server,
      new SslConnectionFactory(sslContextFactory,HttpVersion.HTTP_1_1.asString()),
      new HttpConnectionFactory(https_config))
    https.setPort(0)
    server.addConnector(https)
    http_config.setSecurePort(https.getLocalPort)


    def httpPort = http.getLocalPort
    def httpsPort = https.getLocalPort

    def start(): Unit = {
      if (server.isStopped) server.start()
//server.join()
    }

    def stop(): Unit = {
      if (server.isRunning) {
        server.stop()
        server.join()
      }
    }
  }
}
