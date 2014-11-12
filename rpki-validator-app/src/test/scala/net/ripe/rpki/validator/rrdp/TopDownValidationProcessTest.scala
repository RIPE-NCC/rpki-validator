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

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import net.ripe.rpki.validator.support.ValidatorTestCase
import java.net.URI
import org.apache.commons.codec.binary.Base64
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil

@RunWith(classOf[JUnitRunner])
class TopDownValidationProcessTest extends ValidatorTestCase {

  // Use a test like this to test the complete process using a real TAL and an RRDP server
  // Commenting out not to break the build..
  //  test("Should do top-down validation") {
  //
  //    val subject = new TopDownValidationProcess()
  //
  //    val TAL = "http://localhost:8080/rpki-ca/ta/ta.cer\n" +
  //              "\n" +
  //              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2LNkCLPJRZmtaEVe\n" +
  //              "s7KJ1EjQflrVFIJEeg1LmcxkaXPMtqdNtawLrrfedJQZaTudFxk0asWmItR7\n" +
  //              "WnP8sSrskpF1ivSZuJtG4XJ15x6rmSxftx1yA/SwgcYdecspY2RxU499ag4s\n" +
  //              "tGXUL4HYWj+vljSXz7lg54tqa2QDJdsaEZvhvUuWQPBYRWhcIkQixv26MlUT\n" +
  //              "cxpYDHn6xQxgiYdSyW9G9peLlzT/WwrbaELgfAndmeBVHXNKYWBIhS5ItkQu\n" +
  //              "HtbrQKVGpH2kmvVx2sRR2lBrdv6V6yrB1e3eIEDo5FRQNWkigHEfmD2IFzdU\n" +
  //              "rzDUFII3FTvAa/JJJKpvN+z6SQIDAQAB"
  //
  //    val trustAnchorFetcher = TrustAnchorFetcher.fromString(TAL)
  //    val objectStore = new InMemoryRepositoryObjectStore()
  //
  //    val result = subject.validateTrustAnchor(trustAnchorFetcher, objectStore)
  //
  //    println(result.validatedObjects)
  //
  //  }

  ignore("Should validate Rob's stuff") {
    
    val tal = "http://akkht.hactrn.net/root.cer\n\n" +
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4bkrPJMv1PmrDYCOihmr\n" +
              "DgcsCwbrU1ObHd3vZeQo+7IudX853X8J4Gn384gHrnVm/jayNVqXe9B8jNwI/iRY\n" +
              "llgbvOnT0zzJzKpdmRw6FHffxyW+ure0KftINyWarRKxFqxZ+Z4ILTLIsPHOJIci\n" +
              "F7MLm/HApH26AOwjToW6oiPpSMNH0sIyfc5YEiNJpVPSeFeAESAa3Vc8MomOLDJU\n" +
              "empE3o4swHPW3GlX/7uGY4TwPiospbHMNkVMYWAU4Xx/nHWvsJE4P6sAyx/ZFhoe\n" +
              "tTkKV5hDGqNmf0Q94pFGhetI8BlPYjkC/gRM7C1egtg06oO0dugaA2Hd14T/lHOV\n" +
              "xQIDAQAB"

    val trustAnchorFetcher = TrustAnchorFetcher.fromString(tal)
    val objectStore = new InMemoryRepositoryObjectStore()
    
    val subject = new TopDownValidationProcess()
    val result = subject.validateTrustAnchor(trustAnchorFetcher, objectStore)
    
    result.validatedObjects.toList.sortBy(_._1).reverse foreach { repoObject =>
      val validatedObject = repoObject._2
      println(s"${repoObject._1} -> valid: ${validatedObject.isValid}")
      
    }
  }

}