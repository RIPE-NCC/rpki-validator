package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.ui.common.WicketUtil;

import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.panel.Panel;

public class RoaValidityPanel extends Panel {

	private static final long serialVersionUID = 1L;

	public RoaValidityPanel(String id, BottomUpRoaValidationResult result) {
		super(id);
        add(new Label("validity", result.isValid() ? "valid" : "invalid"));
        add(WicketUtil.getStatusImage("checkmark", result.isValid()));
	}


}
