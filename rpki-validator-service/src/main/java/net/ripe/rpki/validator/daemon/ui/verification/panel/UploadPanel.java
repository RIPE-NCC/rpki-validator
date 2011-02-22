package net.ripe.rpki.validator.daemon.ui.verification.panel;

import net.ripe.rpki.validator.daemon.ui.common.AbstractPanel;
import net.ripe.rpki.validator.daemon.ui.common.NavigationalCallbackHandler;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.util.lang.Bytes;

public class UploadPanel extends AbstractPanel<FileUpload> {
    private static final long serialVersionUID = 6448751150586724591L;
    private static final int MAX_SIZE_IN_KB = 100;
    private Integer maxSize;

    private final NavigationalCallbackHandler<byte[]> callbackHandler;

    public UploadPanel(String id, NavigationalCallbackHandler<byte[]> callbackHandler) {
        this(id, MAX_SIZE_IN_KB, callbackHandler);
    }

    public UploadPanel(String id, Integer maxSize, NavigationalCallbackHandler<byte[]> callbackHandler) {
        super(id);

        this.maxSize = maxSize;
        this.callbackHandler = callbackHandler;

        Model<FileUpload> model = new Model<FileUpload>();
        setDefaultModel(model);

        initPanel(model);
    }

    private void initPanel(IModel<FileUpload> model) {
        add(new FeedbackPanel("feedbackPanel"));

        Form<FileUpload> form = new UploadForm("uploadForm");

        FileUploadField fileInput = new FileUploadField("fileInput", model);
        fileInput.setRequired(true);
        form.add(fileInput);

        add(form);
    }

    private class UploadForm extends Form<FileUpload> {

        private static final long serialVersionUID = 2215584856791846548L;

        public UploadForm(String id) {
            super(id);

            setMultiPart(true);
            setMaxSize(Bytes.kilobytes(maxSize));
        }

        @Override
        protected void onSubmit() {
            FileUpload fileUpload = UploadPanel.this.getPanelModelObject();

            byte[] bytes = fileUpload.getBytes();

            callbackHandler.callback(bytes);
        }
    }
}
