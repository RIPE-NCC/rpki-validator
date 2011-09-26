/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.rpki.validator.daemon.service;

import net.ripe.certification.validator.util.TrustAnchorLocator;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsParser;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.util.FileResourceUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;

@Component("roaValidationService")
public class BottomUpRoaValidationServiceImpl implements BottomUpRoaValidationService {

    @Value("${tal.location}")
    private String talLocation;

    private BottomUpRoaValidationCommand validationCommand;

    public BottomUpRoaValidationServiceImpl() {
        validationCommand = new BottomUpRoaValidationCommand();
    }

    @Override
    public BottomUpRoaValidationResult validateRoa(byte[] encodedObject) {
        RoaCms roaCms = parseEncodedObjectAsRoa(encodedObject);

        if (roaCms == null) {
            return new BottomUpRoaValidationResult();
        }

        File talFile = FileResourceUtil.findFileInPathOrConfigPath(talLocation);

        ValidationResult validationResults = validationCommand.validate(roaCms, TrustAnchorLocator.fromFile(talFile));
        return new BottomUpRoaValidationResult(roaCms, validationResults);
    }

    private RoaCms parseEncodedObjectAsRoa(byte[] encodedObject) {
        try {
            RoaCmsParser parser = new RoaCmsParser();
            parser.parse("", encodedObject);
            return parser.getRoaCms();
        } catch (IllegalArgumentException e) {
            return null; // ROA parsing failed
        }
    }

    /**
     * For unit testing
     *
     * @deprecated
     */
    void setValidationCommand(BottomUpRoaValidationCommand validationCommand) {
        this.validationCommand = validationCommand;
    }

    /**
     * For unit testing
     *
     * @deprecated
     */
    void setTalLocation(String talLocation) {
        this.talLocation = talLocation;
    }
}
