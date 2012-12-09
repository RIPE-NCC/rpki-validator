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
package net.ripe.rpki.validator
package benchmark

import org.clapper.argot._
import org.clapper.argot.ArgotConverters._
import org.apache.commons.io.FileUtils
import java.io.File
import scala.collection.JavaConverters._
import java.util

object BenchmarkOptions {

  val DEFAULT_VALIDATION_RUN_COUNT = 10
  var DEFAULT_VALIDATION_THREAD_COUNT = 1

  def parse(args: Array[String]): Either[String, BenchmarkOptions] = try {
    Right(new BenchmarkOptions(args))
  } catch {
    case e: ArgotUsageException => Left(e.getMessage())
  }
}

class BenchmarkOptions(args: Array[String]) {

  private val parser = new ArgotParser(programName = "rpki-benchmarkr")

  private val validationRunCountOption = parser.option[Int](List("v", "validation-count"), "Validation run count", "Number of validation runs. Default: " + BenchmarkOptions.DEFAULT_VALIDATION_RUN_COUNT)
  private val threadCountOption = parser.option[Int](List("t", "thread-count"), "Validation thread count", "Number of threads used in validation runs. Default: " + BenchmarkOptions.DEFAULT_VALIDATION_THREAD_COUNT)
  private val httpSupportOption = parser.flag[Boolean](List("http-support"), "Use http instead of rsync for retrieving objects from rpki repositories. (Experimental)")
  private val talFileNameOption = parser.option[File](List("f", "tal-file"), "Trust anchor locator file", "Specify the trust anchor locator file used for validation.") {
    (s, opt) =>
      val file = new File(s)
      if (!file.exists) parser.usage("Tal file \"" + file + "\" does not exist.")
      file
  }

  parser.parse(args)

  val httpSupport: Boolean = httpSupportOption.value.getOrElse(false)
  val validationRunCount: Int = validationRunCountOption.value.getOrElse(BenchmarkOptions.DEFAULT_VALIDATION_RUN_COUNT)
  val threadCount: Int = threadCountOption.value.getOrElse(BenchmarkOptions.DEFAULT_VALIDATION_THREAD_COUNT)
  val talFile: File = talFileNameOption.value.getOrElse(parser.usage(talFileNameOption.description))
}
