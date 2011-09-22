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
package config

import grizzled.slf4j.Logger
import org.eclipse.jetty.server.Server
import org.apache.commons.io.FileUtils
import java.io.File
import scala.collection.JavaConverters._
import net.ripe.certification.validator.util.TrustAnchorExtractor
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.rtr.RTRServer
import models._

object Main {
  val logger = Logger[this.type]

  var trustAnchors: TrustAnchors = null
  var roas: Roas = null

  def main(args: Array[String]) {
    trustAnchors = loadTrustAnchors()
    roas = Roas.fetch(trustAnchors)
    runServer()
    RTRServer.startServer()
  }

  def loadTrustAnchors(): TrustAnchors = {
    import java.{util => ju}
    val tals = new ju.ArrayList(FileUtils.listFiles(new File("conf/tal"), Array("tal"), false).asInstanceOf[java.util.Collection[File]])
    TrustAnchors.load(tals.asScala, "tmp/tals")
  }

  def setup(server: Server): Server = {
    import org.eclipse.jetty.servlet._
    import org.scalatra._

    val root = new ServletContextHandler(server, "/", ServletContextHandler.SESSIONS)
    root.setResourceBase(getClass().getResource("/public").toString())
    val defaultServletHolder = new ServletHolder(new DefaultServlet())
    defaultServletHolder.setName("default")
    defaultServletHolder.setInitParameter("dirAllowed", "false")
    root.addServlet(defaultServletHolder, "/*")
    root.addFilter(new FilterHolder(new WebFilter {
      def trustAnchors = Main.trustAnchors
      def roas = Main.roas
    }), "/*", FilterMapping.ALL)
    server.setHandler(root)
    server
  }

  private def runServer(): Unit = {
    val port = 8080
    val server = setup(new Server(port))

    Runtime.getRuntime().addShutdownHook(new Thread {
      override def run() {
        server.stop()
        logger.info("Bye, bye...")
      }
    })
    server.start()
    logger.info("Welcome to the RIPE NCC RPKI Validator, now available on port " + port + ". Hit CTRL+C to terminate.")
  }
}
