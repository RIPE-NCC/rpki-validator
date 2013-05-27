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

import org.clapper.argot._
import org.clapper.argot.ArgotConverters._

object Options {

  val DEFAULT_RTR_PORT = 8282
  val DEFAULT_HTTP_PORT = 8080
  val DEFAULT_DATA_FILE_NAME = "data/configuration.json"

  def parse(args: Array[String]): Either[String, Options] = try {
    Right(new Options(args))
  } catch {
    case e: ArgotUsageException => Left(e.getMessage)
  }
}

class Options(args: Array[String]) {
  private val DefaultFeedbackUri = "https://ba-feedback-server.ripe.net/metrics/rpki-validator"

  private val parser = new ArgotParser(programName = "rpki-validator")

  private val rtrPortOption = parser.option[Int](List("r", "rtr-port"), "RTR-PORT", "The port the rtr-rpki tcp server will listen on. Default: " + Options.DEFAULT_RTR_PORT)
  private val httpPortOption = parser.option[Int](List("h", "http-port"), "HTTP-PORT", "The http port the for the User Interface. Default: " + Options.DEFAULT_HTTP_PORT)
  private val noCloseOption = parser.flag[Boolean](List("n", "no-close-on-error"), "Stop the server from closing connections when it receives fatal errors.")
  private val noNotifyOption = parser.flag[Boolean](List("s", "silent"), "Stop the server from sending notify messages when it has updates.")
  private val dataFileNameOption = parser.option[String](List("f", "data-file"), "FILE", "Specify the data file used to load and store configuration. Default: " + Options.DEFAULT_DATA_FILE_NAME)
  private val feedbackUriOption = parser.option[String](List("feedback-uri"), "URI", "Specify the URI used to send back feedback metrics to RIPE NCC. Default: " + DefaultFeedbackUri)

  def rtrPort: Int = rtrPortOption.value.getOrElse(Options.DEFAULT_RTR_PORT)
  def httpPort: Int = httpPortOption.value.getOrElse(Options.DEFAULT_HTTP_PORT)
  def noCloseOnError: Boolean = noCloseOption.value.getOrElse(false)
  def noNotify: Boolean = noNotifyOption.value.getOrElse(false)
  def dataFileName: String = dataFileNameOption.value.getOrElse(Options.DEFAULT_DATA_FILE_NAME)
  def feedbackUri: String = feedbackUriOption.value.getOrElse(DefaultFeedbackUri)

  parser.parse(args)
}
