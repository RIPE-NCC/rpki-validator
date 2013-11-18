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
package net.ripe.rpki.validator.models

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.mock.MockitoSugar
import java.net.URI
import net.ripe.rpki.commons.validation.{ValidationString, ValidationStatus, ValidationCheck}
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ValidatedObjectsTest extends ValidatorTestCase with MockitoSugar {

  def makeListOfValidObjects(number: Int) = for (nr <- 1 until number + 1) yield {
    ValidObject(
      URI.create(s"rsync://some.host/repo/valid-$nr.unk"),
      Set(new ValidationCheck(ValidationStatus.PASSED, ValidationString.VALIDATOR_READ_FILE)),
      new UnknownCertificateRepositoryObject(new Array[Byte](0)))
  }

  def makeListOfInvalidObjects(number: Int) = for (nr <- 1 until number + 1) yield {
    InvalidObject(
      URI.create(s"rsync://some.host/repo/invalid-$nr.unk"),
      Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_READ_FILE)))
  }

  test("Should add repository error when at least one error was found and there is a 10% or more drop in valid object count") {

    val oldValidatedObjects = makeListOfValidObjects(10)
    val newObjects = makeListOfValidObjects(8) ++ makeListOfInvalidObjects(1)
    val taUri = URI.create("rsync://some/ta.cer")

    val objectsWithRepositoryHealth: Seq[ValidatedObject] = ValidatedObjects.getValidatedObjectsWithRepositoryHealth(taUri, oldValidatedObjects, newObjects)

    assert(objectsWithRepositoryHealth.contains(
      new InvalidObject(
        taUri,
        Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_DROP, "10", "9")))))
  }

  test("Should NOT add repository error when at least one error was found and there is a less than 10% drop in valid object count") {

    val oldValidatedObjects = makeListOfValidObjects(10)
    val newObjects = makeListOfValidObjects(9) ++ makeListOfInvalidObjects(1)
    val taUri = URI.create("rsync://some/ta.cer")

    val objectsWithRepositoryHealth: Seq[ValidatedObject] = ValidatedObjects.getValidatedObjectsWithRepositoryHealth(taUri, oldValidatedObjects, newObjects)

    assert(!objectsWithRepositoryHealth.contains(
      new InvalidObject(
        taUri,
        Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_DROP, "10", "10")))))
  }

  test("Should NOT add repository error there is a drop in object count, but no errors were found") {

    val oldValidatedObjects = makeListOfValidObjects(10)
    val newObjects = makeListOfValidObjects(5)
    val taUri = URI.create("rsync://some/ta.cer")

    val objectsWithRepositoryHealth: Seq[ValidatedObject] = ValidatedObjects.getValidatedObjectsWithRepositoryHealth(taUri, oldValidatedObjects, newObjects)

    assert(!objectsWithRepositoryHealth.contains(
      new InvalidObject(
        taUri,
        Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_DROP, "10", "5")))))
  }

}
