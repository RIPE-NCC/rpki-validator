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
package net.ripe.rpki.validator.rrdp

import java.net.URI
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationOptions
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.rpki.validator.models.ValidObject
import net.ripe.rpki.validator.models.ValidatedObject
import scala.collection.JavaConverters._
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.crypto.crl.CrlLocator
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.rpki.commons.validation.ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_FOUND
import net.ripe.rpki.commons.validation.ValidationCheck
import net.ripe.rpki.commons.validation.ValidationStatus

class TopDownValidationProcess(maxStaleDays: Int = 0, enableLooseValidation: Boolean = false) {

  def validateTrustAnchor(trustAnchorFetcher: TrustAnchorFetcher, repositoryObjectStore: RepositoryObjectStore, knownFetchers: List[RrdpFetcher] = List.empty): TopDownValidationResult = trustAnchorFetcher.fetch match {
    case invalid: InvalidObject => ??? // TODO Handle failure to retrieve/validate TA.. report nicely and/or try to find in cache?
    case validTa: ValidObject => {
      val taCert = validTa.repositoryObject.asInstanceOf[X509ResourceCertificate] // if we can't cast this, it wouldn't be valid
      validateForCertificate(new CertificateRepositoryObjectValidationContext(validTa.uri, taCert), repositoryObjectStore, knownFetchers)
    }
  }

  private def validateForCertificate(certificateValidationContext: CertificateRepositoryObjectValidationContext, repositoryObjectStore: RepositoryObjectStore, knownFetchers: List[RrdpFetcher] = List.empty): TopDownValidationResult = {

    var newFetchers: List[RrdpFetcher] = List.empty

    val validationOptions = new ValidationOptions

    /**
     * Checks if the RRDP notify URI for this certificate is known, and if not: adds it to the list and updates it to make sure our cache is recent
     */
    def updateCacheIfNeeded = {

      def findNewFetcher(certificate: X509ResourceCertificate): Option[RrdpFetcher] = {
        val notifyUri = certificate.getRrdpNotifyUri()
        knownFetchers.find(_.notifyUri.equals(notifyUri)) match {
          case Some(fetcher) => None
          case None => {
            val fetcher = RrdpFetcher.initialise(notifyUri)
            Some(fetcher)
          }
        }
      }

      /**
       * gets updates and stores all objects
       */
      def updateFetcher(fetcher: RrdpFetcher) = fetcher.update match {
        case withUpdates: RrdpFetcherWithUpdates => {
          repositoryObjectStore.rememberAll(withUpdates.updates)
          withUpdates.fetcher
        }
        case noUpdates: RrdpFetcherWithoutUpdates => noUpdates.fetcher // weird case, should not happen
        case RrdpFetcherSessionLost => ??? // even more weird, we just made this thing..
      }

      findNewFetcher(certificateValidationContext.getCertificate) match {
        case Some(fetcher) => {
          val updatedFetcher = updateFetcher(fetcher)
          newFetchers = newFetchers :+ updatedFetcher
        }
        case None => // nothing to see, move along
      }
    }

    /**
     * Finds the ONE crl for this MFT. Will only return CRL if
     * there is exactly one CRL on the MFT, and it's in the cache (RFCs say there MUST be exactly one)
     */
    def findCrlForManifest(mft: ManifestCms): Option[ValidX509Crl] = {
      val filesOnMft = mft.getFiles().asScala
      if (filesOnMft.count(_._1.endsWith(".crl")) == 1) {
        val crlHash = ReferenceHash.fromManifestHash(filesOnMft.find(_._1.endsWith(".crl")).get._2)
        repositoryObjectStore.retrieve(crlHash) match {
          case Some(crl: X509Crl) => {
            val crlLocation = mft.getCrlUri // Most likely correct..
            val validationResult = ValidationResult.withLocation(crlLocation)
            val crlLocator = new CrlLocatorWithCrl(crl)

            crl.validate(crlLocation.toString, certificateValidationContext, crlLocator, validationOptions, validationResult)

            if (!validationResult.hasFailures()) {
              Some(ValidX509Crl(crlLocation, crl, validationResult))
            } else {
              None // CRL found but was invalid
            }
          }
          case _ => None // No CRL in cache
        }
      } else {
        None // Manifest does not have exactly one CRL; i.e. 0 or 2 or more..
      }
    }

    def findLatestValidManifestAndCrl(): Option[ValidMftAndCrl] = {

      val mftAkiHash = ReferenceHash.fromBytes(certificateValidationContext.getCertificate.getSubjectKeyIdentifier)

      repositoryObjectStore.retrieveLatestManifest(mftAkiHash) match {
        case None => None
        case Some(mft: ManifestCms) => findCrlForManifest(mft) match {
          case None => {
            // No valid CRL for this one, forget about it and try finding another one
            repositoryObjectStore.forgetManifest(mft)
            findLatestValidManifestAndCrl
          }
          case Some(validCrl) => {
            // validate manifest
            val mftLocation = certificateValidationContext.getManifestURI
            val validationResult = ValidationResult.withLocation(mftLocation)
            val crlLocator = new CrlLocatorWithCrl(validCrl.crl)

            mft.validate(mftLocation.toString, certificateValidationContext, crlLocator, validationOptions, validationResult)
            if (!validationResult.hasFailures()) {
              Some(ValidMftAndCrl(ValidMft(mftLocation, mft, validationResult), validCrl))
            } else {
              // No valid CRL for this one, forget about it and try finding another one
              repositoryObjectStore.forgetManifest(mft)
              findLatestValidManifestAndCrl
            }
          }
        }
      }
    }

    def validatePublishedObjects(mftAndCrl: ValidMftAndCrl): List[ValidatedObject] = {
      val mft = mftAndCrl.validMft.mft
      val crlLocator = new CrlLocatorWithCrl(mftAndCrl.validCrl.crl)
      mft.getFiles().asScala.filterNot(_._1.endsWith(".crl")).map { entry =>
        val name = entry._1
        val hash = ReferenceHash.fromManifestHash(entry._2)

        val location = certificateValidationContext.getRepositoryURI.resolve(name)

        repositoryObjectStore.retrieve(hash) match {
          case None => InvalidObject(location, Set(new ValidationCheck(ValidationStatus.ERROR, VALIDATOR_REPOSITORY_OBJECT_NOT_FOUND, location.toString)))
          case Some(cro) => {
            val validationResult = ValidationResult.withLocation(location)
            cro.validate(location.toString, certificateValidationContext, crlLocator, validationOptions, validationResult)
            if (!validationResult.hasFailures) {
              ValidObject(location, validationResult.getAllValidationChecksForCurrentLocation().asScala.toSet, cro)
            } else {
              InvalidObject(location, validationResult.getAllValidationChecksForCurrentLocation().asScala.toSet)
            }
          }
        }

      }.toList

    }

    updateCacheIfNeeded

    // get latest validated manifest
    findLatestValidManifestAndCrl() match {
      case None => ??? // TODO: carry over why mft and/or crl were invalid
      case Some(mftAndCrl) => {
        val validatedObjects = validatePublishedObjects(mftAndCrl)
        val validCaCertificates = validatedObjects.collect {
          case ValidObject(uri, checks, cro) if cro.isInstanceOf[X509ResourceCertificate] && cro.asInstanceOf[X509ResourceCertificate].isCa => ValidCaCertificate(uri, cro.asInstanceOf[X509ResourceCertificate])
        }

        val childResults = validCaCertificates.toParArray.map { validCert => // TODO: Measure if using a parArray really helps to speed things up by doing the validation of child leaves in parallel
          val childResources = validCert.cert.deriveResources(certificateValidationContext.getResources())
          val childContext = new CertificateRepositoryObjectValidationContext(validCert.uri, validCert.cert, childResources)
          validateForCertificate(childContext, repositoryObjectStore, knownFetchers)
        }

        val objectsFoundHere = mftAndCrl.toValidObjects ++ validatedObjects.map(obj => obj.uri -> obj)
        val fetchersFoundHere = newFetchers

        // Combine this result with child results
        val allObjectsFound = childResults.foldLeft(objectsFoundHere)((updated, childResult) => updated ++ childResult.validatedObjects)
        val allFetchersFound = childResults.foldLeft(fetchersFoundHere)((updated, childResult) => updated ++ childResult.newFetchers)

        TopDownValidationResult(allObjectsFound, allFetchersFound)
      }
    }
  }

}

class CrlLocatorWithCrl(crl: X509Crl) extends CrlLocator {
  override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult) = crl
}

case class ValidX509Crl(uri: URI, crl: X509Crl, validationResult: ValidationResult)
case class ValidMft(uri: URI, mft: ManifestCms, validationResult: ValidationResult)
case class ValidMftAndCrl(validMft: ValidMft, validCrl: ValidX509Crl) {
  def toValidObjects = {
    Map (validMft.uri -> ValidObject(validMft.uri, validMft.validationResult.getAllValidationChecksForCurrentLocation().asScala.toSet, validMft.mft),
         validCrl.uri -> ValidObject(validCrl.uri, validCrl.validationResult.getAllValidationChecksForCurrentLocation().asScala.toSet, validCrl.crl))
  }
}
case class ValidCaCertificate(uri: URI, cert: X509ResourceCertificate)

case class TopDownValidationResult(validatedObjects: Map[URI, ValidatedObject], newFetchers: List[RrdpFetcher] = List.empty)

