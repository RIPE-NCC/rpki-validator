package net.ripe.certification.validator.fetchers;

import java.net.URI;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.utils.Specification;

public interface CertificateRepositoryObjectFetcher extends CrlLocator {

    void prefetch(URI uri, ValidationResult result);

    ManifestCms getManifest(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result);

    CertificateRepositoryObject getObject(URI uri, CertificateRepositoryObjectValidationContext context, Specification<byte[]> fileContentSpecification, ValidationResult result);
}
