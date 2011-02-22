package net.ripe.rpki.validator.daemon.ui.verification;

import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationService;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import org.apache.wicket.model.Model;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

public class RpkiValidationResultPageTest extends AbstractWicketTest {

    private BottomUpRoaValidationService service;

    @Before
    public void setUp() {

        service = createMock(BottomUpRoaValidationService.class);

        getMockContext().putBean("roaValidationService", service);
    }

    @Test
    public void shouldRenderForInvalidRoa() {
        byte[] contents = {0};

        expect(service.validateRoa(contents)).andReturn(new BottomUpRoaValidationResult());

        replay(service);

        getTester().startPage(new RpkiValidationResultPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RpkiValidationResultPage.class);

        String validity = getTester().getComponentFromLastRenderedPage("validity").getDefaultModelObjectAsString();
        assertEquals("invalid", validity);

        verify(service);
    }

    @Test
    public void shouldRenderForValidRoa() {
        byte[] contents = {0};

        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(RoaCmsObjectMother.getRoaCms(), new ValidationResult());
        expect(service.validateRoa(contents)).andReturn(result);

        replay(service);

        getTester().startPage(new RpkiValidationResultPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RpkiValidationResultPage.class);

        String validity = getTester().getComponentFromLastRenderedPage("validity").getDefaultModelObjectAsString();
        assertEquals("valid", validity);

        verify(service);
    }

}
