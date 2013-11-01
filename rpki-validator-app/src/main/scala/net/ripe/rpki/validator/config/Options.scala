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
import java.io.File

object Options {

  val DefaultRtrPort = 8282
  val DefaultHttpPort = 8080

  val DefaultDataDir = "data"
  val DefaultConfigDirPath = "conf"
  val DefaultTalDirPath = "conf/tal"
  val DefaultWorkDir = "tmp"
  val DefaultAccessLogFile = "log/access.log"

  def parse(args: Array[String]): Either[String, Options] = try {
    Right(new Options(args))
  } catch {
    case e: ArgotUsageException => Left(e.getMessage)
  }

  val defaults = new Options(Array.empty[String])
}

class Options(args: Array[String]) {
  private val DefaultFeedbackUri = "https://ba-feedback-server.ripe.net/metrics/rpki-validator"

  private val parser = new ArgotParser(programName = "rpki-validator")

  private val rtrPortOption = parser.option[Int](List("r", "rtr-port"), "RTR-PORT", "The port the rtr-rpki tcp server will listen on. Default: " + Options.DefaultRtrPort)
  private val httpPortOption = parser.option[Int](List("h", "http-port"), "HTTP-PORT", "The http port the for the User Interface. Default: " + Options.DefaultHttpPort)
  private val noCloseOption = parser.flag[Boolean](List("n", "no-close-on-error"), "Stop the server from closing connections when it receives fatal errors.")
  private val noNotifyOption = parser.flag[Boolean](List("s", "silent"), "Stop the server from sending notify messages when it has updates.")
  private val feedbackUriOption = parser.option[String](List("feedback-uri"), "URI", "Specify the URI used to send back feedback metrics to RIPE NCC. Default: " + DefaultFeedbackUri)

  private val optionalDataDirPath = parser.option[String](List("d", "data-dir"), "DATA_DIR", "Specify the data file used to load and store configuration. Default: " + Options.DefaultDataDir)
  private val optionalConfigDirPath = parser.option[String](List("c", "config-dir"), "CONFIG_DIR", "Alternative base path for configuration files. Default: " + Options.DefaultConfigDirPath)
  private val optionalTalDirPath = parser.option[String](List("t", "tal-dir"), "TAL_DIR", "Alternative path for TAL files. Default: " + Options.DefaultTalDirPath)
  private val optionalWorkDirPath = parser.option[String](List("w", "work-dir"), "WORK_DIR", "Alternative path for work dir, used to download files with rsync. Default: " + Options.DefaultWorkDir)
  private val optionalLogDirAccessLogFile = parser.option[String](List("a", "access-log"), "ACCESS_LOG", "Alternative path to access log file. Default: " + Options.DefaultAccessLogFile)

  def rtrPort: Int = rtrPortOption.value.getOrElse(Options.DefaultRtrPort)
  def httpPort: Int = httpPortOption.value.getOrElse(Options.DefaultHttpPort)
  def noCloseOnError: Boolean = noCloseOption.value.getOrElse(false)
  def noNotify: Boolean = noNotifyOption.value.getOrElse(false)

  def feedbackUri: String = feedbackUriOption.value.getOrElse(DefaultFeedbackUri)

  private def resolveFile(path: String, fileName: String): File = new File(path + File.separator + fileName)


  def dataFileLocation = optionalDataDirPath.value match {
    case None => resolveFile(Options.DefaultDataDir, "data.json")
    case Some(path) => resolveFile(path, "data.json")
  }

  def log4jConfigurationFileLocation = optionalConfigDirPath.value match {
    case None => resolveFile(Options.DefaultConfigDirPath , "log4j.xml")
    case Some(path) => resolveFile(path, "log4j.xml")
  }

  def talDirLocation = new File(optionalTalDirPath.value.getOrElse(Options.DefaultTalDirPath))
  def workDirLocation = new File(optionalWorkDirPath.value.getOrElse(Options.DefaultWorkDir))
  def accessLogFileName = optionalLogDirAccessLogFile.value.getOrElse(Options.DefaultAccessLogFile)

  parser.parse(args)
}
