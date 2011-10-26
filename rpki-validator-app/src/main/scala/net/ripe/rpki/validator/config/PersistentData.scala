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

import org.apache.commons.io.FileUtils
import net.liftweb.json._
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import grizzled.slf4j.Logging
import models._
import java.io.{FileNotFoundException, File, IOException}

case class PersistentData(schemaVersion: Int = 0, filters: Filters = Filters(), whitelist: Whitelist = Whitelist())

class PersistentDataSerialiser {

  object AsnSerialiser extends Serializer[Asn] {
    def deserialize(implicit format: Formats) = {
      case (_, JInt(i)) => new Asn(i.longValue())
    }

    def serialize(implicit format: Formats) = {
      case asn: Asn => new JInt(new BigInt(asn.getValue()))
    }
  }

  object IpRangeSerialiser extends Serializer[IpRange] {
    def deserialize(implicit format: Formats) = {
      case (_, JString(s)) => IpRange.parse(s)
    }

    def serialize(implicit format: Formats) = {
      case range: IpRange => new JString(range.toString)
    }
  }

  implicit val formats: Formats = DefaultFormats + AsnSerialiser + IpRangeSerialiser

  def serialise(data: PersistentData) = Serialization.write(data)

  def deserialise(json: String): PersistentData = Serialization.read[PersistentData](json)
}

object PersistentDataSerialiser extends PersistentDataSerialiser with Logging {
  def write(data: PersistentData, file: File) {
    file.getParentFile.mkdirs()
    val tempFile: File = File.createTempFile("rkpi", "dat", file.getParentFile)
    FileUtils.writeStringToFile(tempFile, serialise(data), "UTF-8")
    if (!tempFile.renameTo(file)) throw new IOException("Error writing file: " + file.getAbsolutePath)
  }

  def read(file: File): Option[PersistentData] = try {
    val json: String = FileUtils.readFileToString(file, "UTF-8")
    Some(deserialise(json))
  } catch {
    case e: FileNotFoundException =>
      info("Config file does not exist: "+ e.getLocalizedMessage)
      None
    case e: IOException =>
      warn("Error reading " + file.getAbsolutePath + ": " + e.getMessage)
      None
  }
}
