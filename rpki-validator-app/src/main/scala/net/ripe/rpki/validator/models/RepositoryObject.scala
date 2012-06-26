package net.ripe.rpki.validator
package models

import net.ripe.commons.certification.CertificateRepositoryObject
import java.net.URI
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.apache.commons.codec.binary.Base64
import net.ripe.commons.certification.cms.manifest.ManifestCms

object RetrievedRepositoryObject {
  
  def apply(url: URI, repositoryObject: CertificateRepositoryObject): RetrievedRepositoryObject = {
    
    val encodedObject = Base64.encodeBase64String(repositoryObject.getEncoded)
    val encodedHash = Base64.encodeBase64String(ManifestCms.hashContents(repositoryObject.getEncoded))
    
    RetrievedRepositoryObject(encodedHash = encodedHash, url = url, encodedObject = encodedObject)
  }
}

case class RetrievedRepositoryObject(encodedHash: String, url: URI, encodedObject: String) {
  
  
}