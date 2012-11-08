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
package fetchers

import java.net.URI
import models.StoredRepositoryObject
import net.ripe.certification.validator.fetchers.RpkiRepositoryObjectFetcher
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.cms.manifest.ManifestCms.FileContentSpecification
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory
import net.ripe.commons.certification.util.Specification
import net.ripe.commons.certification.util.Specifications
import net.ripe.commons.certification.validation.ValidationString.VALIDATOR_FILE_CONTENT
import net.ripe.commons.certification.validation.ValidationString.VALIDATOR_READ_FILE
import net.ripe.commons.certification.validation.ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE
import net.ripe.commons.certification.validation.ValidationString.VALIDATOR_REPOSITORY_INCONSISTENT
import net.ripe.commons.certification.validation.ValidationString.VALIDATOR_REPOSITORY_UNKNOWN
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.validation.ValidationLocation
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.ValidationString
import scala.collection.JavaConverters._
import store.RepositoryObjectStore

class ConsistentObjectFetcher(remoteObjectFetcher: RemoteObjectFetcher, store: RepositoryObjectStore) extends RpkiRepositoryObjectFetcher {

  /**
   * Pass this on to the remote object fetcher
   */
  override def prefetch(uri: URI, result: ValidationResult) = remoteObjectFetcher.prefetch(uri, result)

  /**
   * Triggers that we fetch all objects on the manifest and check that it is a consistent set.
   *
   * If not, we return the old manifest we had (or nothing if we didn't have it), and warn that no consistent set could be retrieved.
   *
   * If it is, we put the new manifest and all the contents in our durable object store for future use, and return the new manifest.
   */
  override def fetch(uri: URI, specification: Specification[Array[Byte]], result: ValidationResult): CertificateRepositoryObject = {
    val storedObject = specification match {
      case filecontentSpec: FileContentSpecification =>
        store.getByHash(filecontentSpec.getHash)
      case _ =>
        fetchAndStoreObject(uri, specification, result)
        store.getLatestByUrl(uri)
    }
    storedObjectToCro(uri, storedObject, result)
  }

  private[this] def fetchAndStoreObject(uri: URI, specification: Specification[Array[Byte]], result: ValidationResult) {
    val cro = Option {
      val fetchResults = new ValidationResult
      fetchResults.setLocation(new ValidationLocation(uri))
      val cro = remoteObjectFetcher.fetch(uri, specification, fetchResults)
      warnAboutFetchFailures(uri, result, fetchResults)
      cro
    }
    cro foreach {
      case manifest: ManifestCms =>
        val fetchResults2 = fetchAndStoreConsistentObjectSet(uri, manifest)
        warnAboutFetchFailures(uri, result, fetchResults2)
      case cro =>
        store.put(StoredRepositoryObject(uri = uri, repositoryObject = cro))
    }
  }

  private[this] def storedObjectToCro(uri: URI, storedObject: Option[StoredRepositoryObject], result: ValidationResult): CertificateRepositoryObject = {
    storedObject match {
      case Some(repositoryObject) =>
        CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.binaryObject.toArray, result)
      case None =>
        result.rejectForLocation(new ValidationLocation(uri), ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE, uri.toString)
        null
    }
  }

  private[this] def fetchAndStoreConsistentObjectSet(manifestUri: URI, mft: ManifestCms): ValidationResult = {
    val fetchResults = new ValidationResult
    fetchResults.setLocation(new ValidationLocation(manifestUri))

    val mftStoredRepositoryObject = StoredRepositoryObject(uri = manifestUri, repositoryObject = mft)

    store.getByHash(mftStoredRepositoryObject.hash.toArray) match {
      case None =>
        val retrievedObjects: Seq[StoredRepositoryObject] = mft.getFileNames.asScala.toSeq.flatMap { fileName =>
            val objectUri = manifestUri.resolve(fileName)
            fetchResults.setLocation(new ValidationLocation(objectUri))
            val cro = Option(remoteObjectFetcher.fetch(objectUri, mft.getFileContentSpecification(fileName), fetchResults))
            cro.map(cro => StoredRepositoryObject(uri = objectUri, repositoryObject = cro))
          }
        if (!fetchResults.hasFailures) {
          store.put(mftStoredRepositoryObject +: retrievedObjects)
        }
      case Some(_) =>
    }

    fetchResults
  }

  private[this] def warnAboutFetchFailures(mftUri: URI, result: net.ripe.commons.certification.validation.ValidationResult, fetchResults: net.ripe.commons.certification.validation.ValidationResult): Unit = {

    import net.ripe.commons.certification.validation.ValidationString._

    val fetchFailureKeys = fetchResults.getFailuresForAllLocations().asScala.map(_.getKey()).toSet

    val oldLocation = result.getCurrentLocation
    result.setLocation(new ValidationLocation(mftUri))
    fetchFailureKeys.foreach {
      case VALIDATOR_READ_FILE =>
        result.warn(VALIDATOR_REPOSITORY_INCOMPLETE, mftUri.toString);
        result.addMetric(VALIDATOR_REPOSITORY_INCOMPLETE, mftUri.toString)
      case VALIDATOR_FILE_CONTENT =>
        result.warn(VALIDATOR_REPOSITORY_INCONSISTENT, mftUri.toString)
        result.addMetric(VALIDATOR_REPOSITORY_INCONSISTENT, mftUri.toString)
      case _ =>
        result.warn(VALIDATOR_REPOSITORY_UNKNOWN, mftUri.toString)
    }
    result.setLocation(oldLocation)
  }
}
