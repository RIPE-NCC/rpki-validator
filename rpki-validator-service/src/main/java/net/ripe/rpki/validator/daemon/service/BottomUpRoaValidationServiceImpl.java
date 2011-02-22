package net.ripe.rpki.validator.daemon.service;

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

        ValidationResult validationResults = validationCommand.validate(roaCms, talFile);
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
