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
import java.util.concurrent.TimeUnit
import com.typesafe.config.{ConfigFactory, Config}
import grizzled.slf4j.Logger

object ApplicationOptions {
  import scala.concurrent.duration._

  private lazy val logger = Logger[this.type]
  private val config: Config = ConfigFactory.load()

  // RIPE currently publishes every 10 minutes, and is the most frequent of the
  // anchors.
  private val minimumValidationInterval = 10.minutes

  def httpPort: Int = config.getInt("ui.http.port")
  def httpKioskEnabled: Boolean = config.getBoolean("ui.kiosk.enable")
  def httpKioskUser: String = config.getString("ui.kiosk.user")
  def httpKioskPass: String = config.getString("ui.kiosk.pass")

  lazy val validationInterval: FiniteDuration = {
    val interval = FiniteDuration(config.getDuration("validation.interval", TimeUnit.MILLISECONDS), TimeUnit.MILLISECONDS)
    if (interval < minimumValidationInterval) {
      logger.warn(s"Validation interval $interval is too short; using $minimumValidationInterval instead.")
      minimumValidationInterval
    } else {
      interval
    }
  }

  def rtrPort: Int = config.getInt("rtr.port")
  def rtrCloseOnError: Boolean = config.getBoolean("rtr.close-on-error")
  def rtrSendNotify: Boolean = config.getBoolean("rtr.send-notify")

  private def resolveFile(path: String, fileName: String): File = new File(path + File.separator + fileName)

  def dataFileLocation = resolveFile(config.getString("locations.datadir"), "data.json")
  def talDirLocation = new File(config.getString("locations.taldir"))
  def workDirLocation = new File(config.getString("locations.workdir"))

  def applicationLogFileName = config.getString("logging.application.file")
  def rtrLogFileName = config.getString("logging.rtr.file")
  def accessLogFileName = config.getString("logging.access.file")
}
