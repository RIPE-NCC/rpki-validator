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

import scala.collection.JavaConverters.asScalaBufferConverter
import scala.collection.JavaConverters.asScalaSetConverter

import models.StoredRepositoryObject
import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
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
import store.RepositoryObjectStore

class ConsistentObjectFetcher(rsyncFetcher: RsyncCertificateRepositoryObjectFetcher, store: RepositoryObjectStore) extends CertificateRepositoryObjectFetcher {

  /**
   * Pass this on to the rsync fetcher
   */
  def prefetch(uri: URI, result: ValidationResult) = rsyncFetcher.prefetch(uri, result)

  /**
   * Triggers that we fetch all objects on the manifest and check that it is a consistent set.
   *
   * If not, we return the old manifest we had (or nothing if we didn't have it), and warn that no consistent set could be retrieved.
   *
   * If it is, we put the new manifest and all the contents in our durable object store for future use, and return the new manifest.
   */
  def getManifest(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): ManifestCms = {
    val fetchResults = fetchConsistentObjectSet(uri)
    warnAboutFetchFailures(uri, result, fetchResults)
    getObject(uri, context, Specifications.alwaysTrue[Array[Byte]], result).asInstanceOf[ManifestCms]
  }

  def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl = {
    getObject(uri, context, Specifications.alwaysTrue[Array[Byte]], result).asInstanceOf[X509Crl]
  }

  def getObject(uri: URI, context: CertificateRepositoryObjectValidationContext, specification: Specification[Array[Byte]], result: ValidationResult) = {

    val storedObject = specification match {
      case filecontentSpec: FileContentSpecification => store.getByHash(filecontentSpec.getHash)
      case _ => store.getLatestByUrl(uri)
    }
    storedObject match {
      case Some(repositoryObject) => CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.binaryObject.toArray)
      case None =>
        result.rejectForLocation(new ValidationLocation(uri), ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE, uri.toString)
        null
    }
  }

  def fetchConsistentObjectSet(manifestUri: URI) = {
    val fetchResults = new ValidationResult
    fetchResults.setLocation(new ValidationLocation(manifestUri))
    val mft = rsyncFetcher.getManifest(manifestUri, null, fetchResults)

    if (!fetchResults.hasFailures) {
      val retrievedObjects: Seq[StoredRepositoryObject] =
        Seq(StoredRepositoryObject(uri = manifestUri, repositoryObject = mft)) ++
          mft.getFileNames.asScala.toSeq.flatMap {
            fileName =>
              val objectUri = manifestUri.resolve(fileName)
              rsyncFetcher.getObject(objectUri, null, mft.getFileContentSpecification(fileName), fetchResults) match {
                case null => Seq.empty
                case repositoryObject => Seq(StoredRepositoryObject(uri = objectUri, repositoryObject = repositoryObject))
              }
          }
      if (!fetchResults.hasFailures) {
        store.put(retrievedObjects)
      }
    }
    fetchResults
  }

  private def warnAboutFetchFailures(mftUri: java.net.URI, result: net.ripe.commons.certification.validation.ValidationResult, fetchResults: net.ripe.commons.certification.validation.ValidationResult): Unit = {

    import net.ripe.commons.certification.validation.ValidationString._

    val fetchFailureKeys = fetchResults.getValidatedLocations.asScala.toSeq.flatMap {
      location => fetchResults.getFailures(location).asScala
    }.map { failure => failure.getKey }.toSet

    val oldLocation = result.getCurrentLocation
    result.setLocation(new ValidationLocation(mftUri))
    fetchFailureKeys.foreach(key => key match {
      case VALIDATOR_READ_FILE =>
        result.warn(VALIDATOR_REPOSITORY_INCOMPLETE, mftUri.toString);
        result.addMetric(VALIDATOR_REPOSITORY_INCOMPLETE, mftUri.toString)
      case VALIDATOR_FILE_CONTENT =>
        result.warn(VALIDATOR_REPOSITORY_INCONSISTENT, mftUri.toString)
        result.addMetric(VALIDATOR_REPOSITORY_INCONSISTENT, mftUri.toString)
      case _ => result.warn(VALIDATOR_REPOSITORY_UNKNOWN, mftUri.toString)
    })
    result.setLocation(oldLocation)
  }

}

