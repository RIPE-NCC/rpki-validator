package net.ripe.certification.validator.commands;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.List;

import net.ripe.certification.validator.fetchers.CachingCertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.ValidatingCertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.output.ObjectFetcherResultLogger;
import net.ripe.certification.validator.runtimeproblems.ValidatorIOException;
import net.ripe.certification.validator.util.UriToFileMapper;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.rsync.Rsync;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import org.apache.commons.io.FileUtils;

public class BottomUpCertificateRepositoryObjectValidator {

	private CertificateRepositoryObjectFetcher chainBuildFetcher;
    private CertificateRepositoryObjectFetcher validationFetcher;
    private CachingCertificateRepositoryObjectFetcher cachingFetcher;
    private SingleObjectWalker singleObjectWalker;
	private ObjectFetcherResultLogger chainBuildResultLogger;
	private File tempDir;
	private List<CertificateRepositoryObjectValidationContext> trustAnchors;


    public BottomUpCertificateRepositoryObjectValidator(List<CertificateRepositoryObjectValidationContext> trustAnchors, CertificateRepositoryObject startingPoint, URI startingPointUri) {
    	chainBuildResultLogger = new ObjectFetcherResultLogger(false);
    	tempDir = getUniqueTempDir();
    	wireUpFetcherForChainBuilding();
        wireUpFetcherForValidation();
        cachingFetcher.updateCache(startingPointUri, startingPoint);
    	singleObjectWalker = new SingleObjectWalker(startingPoint, startingPointUri, chainBuildFetcher, chainBuildResultLogger, validationFetcher);
    	this.trustAnchors = trustAnchors;
    }

    File getTempDirectory() {
    	return tempDir;
    }

    public ValidationResult validate() {
    	ValidationResult result = singleObjectWalker.execute(trustAnchors);
    	try {
    		FileUtils.deleteDirectory(tempDir);
    		return result;
    	} catch (IOException e) {
    		throw new ValidatorIOException("Could not delete temp directory: " + tempDir, e);
    	}
    }

    private void wireUpFetcherForValidation() {
        ValidatingCertificateRepositoryObjectFetcher validatingCertificateRepositoryObjectFetcher = new ValidatingCertificateRepositoryObjectFetcher(cachingFetcher);
        NotifyingCertificateRepositoryObjectFetcher notifyingCertificateRepositoryObjectFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingCertificateRepositoryObjectFetcher);
        notifyingCertificateRepositoryObjectFetcher.addCallback(new ObjectFetcherResultLogger());
        CachingCertificateRepositoryObjectFetcher cachingCertificateRepositoryObjectFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingCertificateRepositoryObjectFetcher);
        validatingCertificateRepositoryObjectFetcher.setOuterMostDecorator(cachingCertificateRepositoryObjectFetcher);
        validationFetcher = cachingCertificateRepositoryObjectFetcher;
    }

    private void wireUpFetcherForChainBuilding() {
        RsyncCertificateRepositoryObjectFetcher rsyncCertificateRepositoryObjectFetcher = new RsyncCertificateRepositoryObjectFetcher(new Rsync(), new UriToFileMapper(tempDir));
        CachingCertificateRepositoryObjectFetcher cachingCertificateRepositoryObjectFetcher = new CachingCertificateRepositoryObjectFetcher(rsyncCertificateRepositoryObjectFetcher);
        NotifyingCertificateRepositoryObjectFetcher notifyingCertificateRepositoryObjectFetcher = new NotifyingCertificateRepositoryObjectFetcher(cachingCertificateRepositoryObjectFetcher);
		notifyingCertificateRepositoryObjectFetcher.addCallback(chainBuildResultLogger);
        cachingFetcher = cachingCertificateRepositoryObjectFetcher;
        chainBuildFetcher =  notifyingCertificateRepositoryObjectFetcher;
    }

	private File getUniqueTempDir() {

		File tmpDirBase = new File(System.getProperty("java.io.tmpdir"));
		File uniqueDir = null;
		try {
			File createTempFile = File.createTempFile("val", null);
			String randomDirName = createTempFile.getName();
			createTempFile.delete();

			uniqueDir = new File(tmpDirBase + File.separator + randomDirName);
			uniqueDir.mkdir();

			return uniqueDir;
		} catch (IOException e) {
			throw new ValidatorIOException("Could not create temp directory", e);
		}
	}

	// for unit testing
    void setSingleObjectWalker(SingleObjectWalker singleObjectWalker ) {
        this.singleObjectWalker = singleObjectWalker;
    }
}
