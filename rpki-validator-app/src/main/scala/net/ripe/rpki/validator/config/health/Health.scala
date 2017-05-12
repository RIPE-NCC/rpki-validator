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
package net.ripe.rpki.validator.config.health

import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.models.ValidatedObjects
import org.joda.time.format.ISODateTimeFormat
import org.joda.time.{DateTime, Instant}

object Health {

  private val timeFormatter = ISODateTimeFormat.dateTimeNoMillis()

  def getValidationTimeStatus(lastUpdated: Seq[Option[DateTime]]): Status = {
    if (lastUpdated.isEmpty)
      Status.ok
    else {
      val (validated, notValidated) = lastUpdated.partition(_.isDefined)
      val tooLongAgo = Instant.now.minus(ApplicationOptions.validationInterval.length * 2)

      lazy val notAllValidated = Status.warning("Not all TA's are validated.")

      if (validated.exists(_.get.isAfter(tooLongAgo)))
        Status.ok
      else if (validated.isEmpty)
        notAllValidated
      else if (notValidated.nonEmpty)
        notAllValidated
      else
        Status.recoverableError("No trust anchors have been validated since " + tooLongAgo.toString(timeFormatter))
    }
  }

  def rsyncHealthCheck(): Status = try {
    val rsync = new Rsync
    rsync.addOptions("--version")
    val rc = rsync.execute()
    if (rc == 0)
      Status.ok("can find and execute rsync")
    else
      Status.validationError("problems executing rsync, make sure you have rsync installed on the path")
  } catch {
    case e: Exception =>
      Status.validationError(e.getMessage)
  }

  def getTasStatus(objects: ValidatedObjects): Map[String, Status] = {
    objects.validationStatusCountByTal.map { case (tal, counters) =>
      val status = counters.get(ValidationStatus.ERROR).map { e =>
        Status.validationError("There " + (if (e == 1) "is 1 error" else s"are $e errors"))
      }.orElse {
        counters.get(ValidationStatus.WARNING).map { w =>
          Status.warning("There " + (if (w == 1) "is 1 error" else s"are $w errors"))
        }
      }.getOrElse(Status.ok)

      tal.getCaName -> status
    }
  }

  def jvmMemoryCheck: Status = {
    val memory = Runtime.getRuntime.totalMemory()
    val freeMemory = Runtime.getRuntime.freeMemory()
    val maxMemory = Runtime.getRuntime.maxMemory()
    if (freeMemory < maxMemory * 0.05)
      Status.recoverableError(s"{ totalMemory: $memory, freeMemory: $freeMemory, maxMemory: $maxMemory }")
    else
      Status.ok(s"{ totalMemory: $memory, freeMemory: $freeMemory, maxMemory: $maxMemory }")
  }

}
