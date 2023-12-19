package yntha.dragonrpc;

import de.jcm.discordgamesdk.Core;
import de.jcm.discordgamesdk.CreateParams;
import de.jcm.discordgamesdk.LogLevel;
import de.jcm.discordgamesdk.Result;
import de.jcm.discordgamesdk.activity.Activity;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import java.io.File;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class DragonRPCPlugin extends ProgramPlugin {
    private static class ActivityParams {
        public String state = "";
        public String details = "";
        public String largeImage = "large-image";
        public String largeText = "Ghidra";
        public String smallImage = "greendragon1080";
        public String smallText = "DragonRPC";
    }

    private Core core;
    private Thread updateThread;
    private Program currentProgram;
    private File currentProgramFile;
    private final CountDownLatch readyLatch = new CountDownLatch(1);

    private static final long CLIENT_ID = 1184963845823922356L;
    private static final CodeUnitFormat codeUnitFormat = new CodeUnitFormat(
            new CodeUnitFormatOptions(
                    CodeUnitFormatOptions.ShowBlockName.ALWAYS,
                    CodeUnitFormatOptions.ShowNamespace.ALWAYS,
                    "",
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    true,
                    new TemplateSimplifier()
            )
    );

    public DragonRPCPlugin(PluginTool plugintool) {
        super(plugintool);
    }

    private void updateActivity(final ActivityParams params) {
        // wait for the core to be ready
        try {
            if (! this.readyLatch.await(5L, TimeUnit.SECONDS)) {
                Msg.error(this, "Error waiting for core to be ready");

                return;
            }
        } catch (InterruptedException e) {
            Msg.error(this, "Error waiting for core to be ready", e);

            return;
        }

        try (final Activity activity = new Activity()) {
            if (! params.state.isEmpty()) {
                activity.setState(params.state);
            }

            if (! params.details.isEmpty()) {
                activity.setDetails(params.details);
            }

            activity.timestamps().setStart(Instant.now());
            activity.assets().setLargeImage(params.largeImage);
            activity.assets().setLargeText(params.largeText);
            activity.assets().setSmallImage(params.smallImage);
            activity.assets().setSmallText(params.smallText);
            
            this.core.activityManager().updateActivity(activity);

        } catch (Exception e) {
            Msg.error(this, "Error setting activity", e);
        }
    }

    private String buildDetailHeader() {
        final Language language = this.currentProgram.getLanguage();
        final LanguageDescription desc = language.getLanguageDescription();
        final Processor processor = language.getProcessor();

        final StringBuilder sbHeader = new StringBuilder();
        sbHeader.append(this.currentProgramFile.getName());
        sbHeader.append(" [");
        sbHeader.append(processor.toString());
        sbHeader.append(":");
        sbHeader.append(desc.getEndian().toShortString());
        sbHeader.append("]");

        return sbHeader.toString();
    }

    private void handleProgramActivated(final ProgramActivatedPluginEvent event) {
        final Program program = event.getActiveProgram();

        if (program == null) { // no program is open. this happens when the tool is closed
            this.currentProgram = null;
            this.currentProgramFile = null;

            return;
        }

        this.currentProgram = program;
        this.currentProgramFile = new File(program.getExecutablePath());

        this.updateActivity(new ActivityParams() {{
            state = "Waiting for location update...";
            details = DragonRPCPlugin.this.buildDetailHeader();
        }});
    }
    
    private void handleProgramLocation(final ProgramLocationPluginEvent event) {
        final Listing listing = this.currentProgram.getListing();
        final Address currentAddress = event.getLocation().getAddress();
        final CodeUnit codeUnit = listing.getCodeUnitAt(currentAddress);

        final StringBuilder sbState = new StringBuilder();
        sbState.append(currentAddress.toString());
        sbState.append(" ");
        sbState.append(DragonRPCPlugin.codeUnitFormat.getRepresentationString(codeUnit));

        this.updateActivity(
            new ActivityParams() {
              {
                state = sbState.toString();
                details = DragonRPCPlugin.this.buildDetailHeader();
              }
        });
    }

    @Override
    protected void init() {
        Msg.info(this, "Initializing DragonRPC");
        Core.initFromClasspath();

        CreateParams params = new CreateParams();
        params.setClientID(DragonRPCPlugin.CLIENT_ID);
        params.setFlags(CreateParams.Flags.NO_REQUIRE_DISCORD);

        this.core = new Core(params);

        // set log level hook. useful for debugging
        this.core.setLogHook(LogLevel.DEBUG, (level, message) -> {
            Msg.debug(this, "Discord SDK: " + message);
        });

        // launch the update thread
        this.updateThread = new Thread(() -> {
            while (! Thread.currentThread().isInterrupted()) {
                this.core.runCallbacks();
                this.readyLatch.countDown();

                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Msg.error(this, "Error sleeping", e);

                    break;
                }
            }
        });

        this.updateThread.start();

        // init activity. should only show that ghidra is open
        this.updateActivity(new ActivityParams() {{
            state = "Waiting for program...";
        }});

        super.init();
    }

    @Override
    public void processEvent(PluginEvent event) {
        switch(event.getClass().getSimpleName()) {
            case "ProgramActivatedPluginEvent":
                Msg.info(this, "ProgramActivatedPluginEvent");
                this.handleProgramActivated((ProgramActivatedPluginEvent) event);

                break;
            case "ProgramLocationPluginEvent":
                Msg.info(this, "ProgramLocationPluginEvent");
                this.handleProgramLocation((ProgramLocationPluginEvent) event);

                break;
            default:
                Msg.info(this, "Unknown event: " + event.getEventName());
                break;
        }

        super.processEvent(event);
    }

    @Override
    protected void cleanup() {
        Msg.info(this, "Cleaning up DragonRPC");

        this.core.activityManager().clearActivity((result) -> {
            if (result != Result.OK) {
                Msg.error(this, "Error clearing activity: " + result);
            }

            this.updateThread.interrupt();
        });

        try {
            this.updateThread.join(5000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        this.core.close();
        super.cleanup();
    }
}