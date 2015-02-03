package net.ripe.rpki.validator.store

import net.ripe.rpki.validator.models.validation._

import scala.collection.immutable

trait Storage {

  def storeCertificate(certificate: CertificateObject)

  def storeManifest(manifest: ManifestObject)

  def storeCrl(crl: CrlObject)

  def storeRoa(Roa: RoaObject)

  def storeBroken(brokenObject: BrokenObject)

  def getCertificate(uri: String): Option[CertificateObject]
  def getCertificates(aki: Array[Byte]): Seq[CertificateObject]

  def getCrls(aki: Array[Byte]): Seq[CrlObject]

  def getRoas(aki: Array[Byte]): Seq[RoaObject]

  def getManifests(aki: Array[Byte]): Seq[ManifestObject]

  def getBroken(url: String): Option[BrokenObject]

  def getBroken: Seq[BrokenObject]

  def delete(url: String, hash: String)
}

/**
 * Generic template for storage singletons.
 */
class Singletons[K,V](create : K => V) {
  private var caches = immutable.Map[K,V]()
  def apply(k: K) : V = {
    synchronized {
      val maybeCache = caches.get(k)
      maybeCache.fold({
        val c = create(k)
        caches = caches + (k -> c)
        c
      })(identity)
    }
  }
}
