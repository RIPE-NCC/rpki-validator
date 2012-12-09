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
import akka.util.duration._
import akka.util.FiniteDuration

object BenchmarkOptions {

  val DEFAULT_VALIDATION_RUN_COUNT = 10
  val DEFAULT_VALIDATION_THREAD_COUNT = 1

  def parse(args: Array[String]): Either[String, BenchmarkOptions] = try {
    Right(new BenchmarkOptions(args))
  } catch {
    case e: ArgotUsageException => Left(e.getMessage())
  }
}

class BenchmarkOptions(args: Array[String]) {

  private val parser = new ArgotParser(programName = "rpki-benchmarkr")

  private val validationRunCountOption = parser.option[Int](List("v", "validation-count"), "COUNT", "Number of validation runs. Default: " + BenchmarkOptions.DEFAULT_VALIDATION_RUN_COUNT)
  private val threadCountOption = parser.option[Int](List("t", "thread-count"), "COUNT", "Number of threads used in validation runs. Default: " + BenchmarkOptions.DEFAULT_VALIDATION_THREAD_COUNT)
  private val httpSupportOption = parser.flag[Boolean](List("http-support"), "Use HTTP instead of rsync for retrieving objects from rpki repositories. (Experimental)")
  private val talFileNameOption = parser.option[File](List("f", "tal-file"), "FILE", "Specify the trust anchor locator file used for validation.") {
    (s, opt) =>
      val file = new File(s)
      if (!file.exists) parser.usage("Tal file \"" + file + "\" does not exist.")
      file
  }
  private val deleteRsyncCacheOption = parser.flag[Boolean](List("delete-rsync-cache"), "Enable deletion of rsync cache after each validation run.")
  private val rampUpPeriodOption = parser.option[Double](List("ramp-up-period"), "SECONDS", "Number of seconds to ramp-up the concurrent threads. Default: 0.0")

  parser.parse(args)

  val httpSupport: Boolean = httpSupportOption.value.getOrElse(false)
  val validationRunCount: Int = validationRunCountOption.value.getOrElse(BenchmarkOptions.DEFAULT_VALIDATION_RUN_COUNT)
  val threadCount: Int = threadCountOption.value.getOrElse(BenchmarkOptions.DEFAULT_VALIDATION_THREAD_COUNT)
  val talFile: File = talFileNameOption.value.getOrElse(parser.usage(talFileNameOption.description))
  val deleteRsyncCache: Boolean = deleteRsyncCacheOption.value.getOrElse(false)
  val rampUpPeriod: FiniteDuration = rampUpPeriodOption.value.getOrElse(0.0).seconds

  private def show(option: SingleValueOption[_], value: Any): String = "--" + option.names.maxBy(_.length) + " " + value
  private def show(option: FlagOption[Boolean]): String = if (option.value.getOrElse(false)) "--" + option.names.maxBy(_.length) else ""

  override def toString = Seq(
      show(talFileNameOption, talFile),
      show(httpSupportOption),
      show(validationRunCountOption, validationRunCount),
      show(threadCountOption, threadCount),
      show(deleteRsyncCacheOption),
      show(rampUpPeriodOption, rampUpPeriod.toMillis / 1000.0)).mkString(" ")
}
