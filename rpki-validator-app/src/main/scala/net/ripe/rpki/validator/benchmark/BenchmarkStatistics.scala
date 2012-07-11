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
package net.ripe.rpki.validator.benchmark

import net.ripe.rpki.validator.statistics.Metric
import java.io.File
import org.apache.commons.io.FileUtils
import org.apache.commons.io.output.FileWriterWithEncoding
import java.io.FileWriter

object BenchmarkData {
  def csvHeader(): String = List("TA Name", "time to prefetch (ms)", "time to validate (ms)", "# objects validated").mkString(",")
}

case class BenchmarkData(timeToPrefetch: Long, timeToValidate: Long, totalObjects: Int) {
  override def toString(): String = {
    "time to prefetch %s, time to validate: %s, total objects: %s" format (timeToPrefetch, timeToValidate, totalObjects)
  }

  def toCsvLine(taName: String): String = {
    List(taName, timeToPrefetch.toString, timeToValidate.toString, totalObjects.toString).mkString(",")
  }
}

/**
 * Saves metrics to disk so that we can analyse benchmark data from multiple instances of this.
 */
object BenchmarkStatistics {

  def save(taName: String, benchmarkData: BenchmarkData) = {
    val statsFileName = new File("stats/stats.out").getCanonicalFile.getAbsolutePath
    val fileWriter = new FileWriter(statsFileName, true)
    try {
      fileWriter.write(benchmarkData.toCsvLine(taName) + "\n")
    } finally {
      fileWriter.close
    }
  }

}