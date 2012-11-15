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
package net.ripe.certification.validator.commands;

import java.io.File;
import java.net.URI;
import java.util.List;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

public class TopDownValidationCommand extends ValidationCommand {

    private File outputDir;

    private List<URI> prefetchUris;

    private boolean roaExportEnabled;

    private File roaExportFile;


    public TopDownValidationCommand(CommandLineOptions options) {
        super(options);
        outputDir = options.getOutputDir();
        prefetchUris = options.getPrefetchUris();
        roaExportEnabled = options.isRoaExportEnabled();
        roaExportFile = options.getRoaExportFile();
    }

    public void execute() {
        List<CertificateRepositoryObjectValidationContext> trustAnchors = getTrustAnchors();
        TopDownCertificateRepositoryValidator validator;
        if (roaExportEnabled) {
            validator = new TopDownCertificateRepositoryValidator(trustAnchors, outputDir, roaExportFile);
        } else {
            validator = new TopDownCertificateRepositoryValidator(trustAnchors, outputDir);
        }
        validator.setPrefetchUris(prefetchUris);
        validator.prepare();
        validator.validate();
    }
}
