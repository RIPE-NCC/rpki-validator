package net.ripe.rpki.validator.daemon.ui.bottomup.validation;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationService;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.RoaValidationPage;

import org.apache.wicket.model.Model;
import org.junit.Before;
import org.junit.Test;

public class RoaValidationPageTest extends AbstractWicketTest {
	
    private BottomUpRoaValidationService service;

    @Before
    public void setUp() {
        service = createMock(BottomUpRoaValidationService.class);
        getMockContext().putBean("roaValidationService", service);
    }

    @Test
    public void shouldRender() {
        getTester().startPage(RoaValidationPage.class);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);
    }
    
    @Test
    public void shouldRenderForInvalidRoa() {
        byte[] contents = {0};

        expect(service.validateRoa(contents)).andReturn(new BottomUpRoaValidationResult());

        replay(service);

        getTester().startPage(new RoaValidationPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);

        String validity = getTester().getComponentFromLastRenderedPage(RoaValidationPage.ID_ROA_VALIDITY+":validity").getDefaultModelObjectAsString();
        assertEquals("invalid", validity);

        verify(service);
    }
    
    
    @Test
    public void shouldRenderForValidRoa() {
        byte[] contents = {0};

        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(RoaCmsObjectMother.getRoaCms(), new ValidationResult());
        expect(service.validateRoa(contents)).andReturn(result);

        replay(service);

        getTester().startPage(new RoaValidationPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);

        String validity = getTester().getComponentFromLastRenderedPage(RoaValidationPage.ID_ROA_VALIDITY+":validity").getDefaultModelObjectAsString();
        assertEquals("valid", validity);

        verify(service);
    }
    
    
}
