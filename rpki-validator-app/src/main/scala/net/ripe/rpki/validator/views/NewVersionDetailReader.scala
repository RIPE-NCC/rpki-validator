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
package net.ripe.rpki.validator.views

import java.net.URI
import org.joda.time.DateTime
import java.io.InputStream
import java.util.Properties
import java.net.URL
import grizzled.slf4j.Logging

class NewVersionDetailReader extends Logging {

  val PUBLIC_LATEST_VERSION_URL = new java.net.URL("https://certification.ripe.net/content/static/validator/latest-version.properties")

  /**
   * Read new version details.
   * Will return None in case of problems or when no new version exists
   */
  def readNewVersionDetails(currentVersion: String): Option[NewVersionDetails] = {
    var in: InputStream = null
    
    try {
      in = readNewVersionPropertiesFile()
      
      val properties = new Properties()
      properties.load(in)
      
      val newVersion = properties.getProperty("version.latest")

      if (newVersion > currentVersion) {
        Some(NewVersionDetails(version = newVersion, url = URI.create(properties.getProperty("version.url"))))
      } else {
        None
      }
    } catch {
      case t: Throwable => {
        error("Could not read latest version details from url: " + PUBLIC_LATEST_VERSION_URL)
        None
      }
    } finally {
      if (in != null) {
        in.close()
      }
    }
  }

  /*
   * Override this for unit testing
   */
  protected def readNewVersionPropertiesFile(): InputStream = {
    PUBLIC_LATEST_VERSION_URL.openStream()
  }
}

case class NewVersionDetails(version: String, url: URI)

object NewVersionAlerter {
  
  val reader = new NewVersionDetailReader
  var enabled = true
  
  def getNewVersionDetails(currentVersion: String) = {
    if (enabled) {
      reader.readNewVersionDetails(currentVersion)
    } else {
      None
    }
  }
  
  
}




