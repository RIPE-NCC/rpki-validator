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

import java.io.File
import java.net.URI
import java.security.cert.CertificateExpiredException
import javax.security.cert.CertificateNotYetValidException

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms.FileContentSpecification
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.util.{Specification, Specifications}
import net.ripe.rpki.commons.validation.{ValidationLocation, ValidationResult, ValidationString}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.models.StoredRepositoryObject
import net.ripe.rpki.validator.store.RepositoryObjectStore

import scala.collection.JavaConverters._

class ConsistentObjectFetcher(remoteObjectFetcher: RsyncRpkiRepositoryObjectFetcher, store: RepositoryObjectStore) extends CertificateRepositoryObjectFetcher {

  /**
   * Pass this on to the remote object fetcher
   */
  override def prefetch(uri: URI, result: ValidationResult) = remoteObjectFetcher.prefetch(uri, result)

  /**
   * Gets the CRL for the current manifest for this context
   */
  override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl = {
    getCurrentManifestForContext(context, result) match {
      case None => null // NO! When we don't have a manifest we don't even look for the CRL
      case Some(mft) =>
        val crlFileName = new File(uri.getPath).getName
        val crlSpecification = mft.getFileContentSpecification(crlFileName)
        storedObjectToCro(uri, store.getByHash(crlSpecification.getHash), result) match {
          case crl: X509Crl => crl
          case _ => null
        }
    }
  }

  /**
   * Get the current manifest for this context
   *
   * Tries to update what that current manifest should be in the process
   */
  override def getManifest(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): ManifestCms = {
    val fetchResult = updateObjectCacheForManifest(uri)
    warnAboutFetchFailures(uri, result, fetchResult)
    getCurrentManifestForContext(context, result).orNull
  }

  private def getCurrentManifestForContext(context: CertificateRepositoryObjectValidationContext, result: ValidationResult): Option[ManifestCms] = {
    val manifestURI: URI = context.getManifestURI
    storedObjectToCro(manifestURI, store.getLatestByUrl(manifestURI), result) match {
      case mft: ManifestCms => Some(mft)
      case _ => None
    }
  }

  override def getObject(uri: URI, context: CertificateRepositoryObjectValidationContext, specification: Specification[Array[Byte]], result: ValidationResult): CertificateRepositoryObject = specification match {
    case fileContentSpec: FileContentSpecification =>
      storedObjectToCro(uri, store.getByHash(fileContentSpec.getHash), result)
    case _ =>
      remoteObjectFetcher.fetch(uri, specification, result)
  }

  def getTrustAnchorCertificate(uri: URI, result: ValidationResult): Option[X509ResourceCertificate] = {
    val fetchResult = ValidationResult.withLocation(uri)
    remoteObjectFetcher.fetch(uri, Specifications.alwaysTrue[Array[Byte]](), fetchResult) match {
      case cert: X509ResourceCertificate =>
        try {
          cert.getCertificate.checkValidity()
        } catch {
          case e: CertificateExpiredException => result.error(ValidationString.NOT_VALID_AFTER, e.toString)
          case e: CertificateNotYetValidException => result.error(ValidationString.NOT_VALID_BEFORE, e.toString)
        }

        store.put(StoredRepositoryObject(uri, cert.getEncoded))
        Some(cert)
      case _ =>
        warnAboutFetchFailures(uri, result, fetchResult)
        storedObjectToCro(uri, store.getLatestByUrl(uri), result) match {
          case storedCert: X509ResourceCertificate => Some(storedCert)
          case _ => None
        }
    }
  }


  /**
   * Get latest manifest and objects from the repository and store them
   * for use by this 'consistent' fetcher if:
   * - A consistent set (manifest plus all objects matching hashes) was retrieved this way, OR
   * - The new set was not consistent, but sadly, it's the best we have
   */
  private[this] def updateObjectCacheForManifest(manifestUri: URI): ValidationResult = {
    val fetchResults = ValidationResult.withLocation(manifestUri)

    fetchRemoteManifest(manifestUri, fetchResults) match {
      case None =>
      case Some(mft) =>
        val mftStoredRepositoryObject = StoredRepositoryObject(uri = manifestUri, binary = mft.getEncoded)

        val retrievedObjects: Seq[StoredRepositoryObject] = mft.getFileNames.asScala.toSeq.flatMap { fileName =>
          val objectUri = manifestUri.resolve(fileName)
          fetchResults.setLocation(new ValidationLocation(objectUri))
          try {
            val bytes = Option(remoteObjectFetcher.fetchContent(objectUri, mft.getFileContentSpecification(fileName), fetchResults))
            bytes.map(b => StoredRepositoryObject(uri = objectUri, binary = b))
          } catch {
            case e: RuntimeException =>
              fetchResults.error(ValidationString.OBJECTS_GENERAL_PARSING, objectUri.toString)
              None
          }
        }

        // Store the manifest and all objects for use, if there are no failures
        if (store.getLatestByUrl(manifestUri).isEmpty || !fetchResults.hasFailures) {
          store.put(mftStoredRepositoryObject +: retrievedObjects)
        }
    }

    fetchResults
  }

  private def fetchRemoteManifest(manifestUri: URI, result: ValidationResult): Option[ManifestCms] = {
    val cro = remoteObjectFetcher.fetch(manifestUri, Specifications.alwaysTrue[Array[Byte]](), result)
    result.rejectIfFalse(cro.isInstanceOf[ManifestCms], ValidationString.VALIDATOR_FETCHED_OBJECT_IS_MANIFEST)

    if (result.hasFailureForCurrentLocation) {
      None
    } else {
      Some(cro.asInstanceOf[ManifestCms])
    }
  }

  private[this] def storedObjectToCro(uri: URI, storedObject: Option[StoredRepositoryObject], result: ValidationResult): CertificateRepositoryObject = {
    storedObject match {
      case Some(repositoryObject) =>
        val oldLocation = result.getCurrentLocation
        result.setLocation(new ValidationLocation(uri))
        val cro = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.binaryObject.toArray, result)
        result.setLocation(oldLocation)
        cro
      case None =>
        result.rejectForLocation(new ValidationLocation(uri), ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE, uri.toString)
        null
    }
  }

  private[this] def warnAboutFetchFailures(uri: URI, result: ValidationResult, fetchResults: ValidationResult): Unit = {

    import net.ripe.rpki.commons.validation.ValidationString._

    val fetchFailureKeys = fetchResults.getFailuresForAllLocations.asScala.map(_.getKey).toSet
    val oldLocation = result.getCurrentLocation
    result.setLocation(new ValidationLocation(uri))
    fetchFailureKeys.foreach {
      case VALIDATOR_RSYNC_COMMAND =>
        result.warn(VALIDATOR_RSYNC_COMMAND, uri.toString)
      case VALIDATOR_READ_FILE =>
        result.warn(VALIDATOR_REPOSITORY_INCOMPLETE, uri.toString)
      case VALIDATOR_FILE_CONTENT =>
        result.warn(VALIDATOR_REPOSITORY_INCONSISTENT, uri.toString)
      case _ =>
        result.warn(VALIDATOR_REPOSITORY_UNKNOWN, uri.toString)
    }
    result.setLocation(oldLocation)
  }
}
