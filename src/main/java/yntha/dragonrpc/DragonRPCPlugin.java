package yntha.dragonrpc;

import de.jcm.discordgamesdk.Core;
import de.jcm.discordgamesdk.CreateParams;
import de.jcm.discordgamesdk.Result;
import de.jcm.discordgamesdk.activity.Activity;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;

import java.time.Instant;

public class DragonRPCPlugin extends ProgramPlugin {
    private Core core;

    public DragonRPCPlugin(PluginTool plugintool) {
        super(plugintool);
    }

    @Override
    protected void init() {
        super.init();
        Core.initFromClasspath();

        CreateParams params = new CreateParams();
        params.setClientID(1184963845823922356L);
        params.setFlags(CreateParams.Flags.NO_REQUIRE_DISCORD);

        this.core = new Core(params);

        // init activity. should only show that ghidra is open
        try (final Activity activity = new Activity()) {
            activity.setState("Waiting for program...");
            activity.timestamps().setStart(Instant.now());
            activity.assets().setLargeImage("large-image");
            activity.assets().setLargeText("Ghidra");
            activity.party().size().setMaxSize(1);

            core.activityManager().updateActivity(activity, (result) -> {
                if (result != Result.OK) {
                    System.out.println("Error updating activity: " + result);
                }
            });
        }
    }

    @Override
    public void processEvent(PluginEvent event) {
        super.processEvent(event);
    }

    @Override
    protected void cleanup() {
        super.cleanup();

        this.core.activityManager().clearActivity((result) -> {
            if (result != Result.OK) {
                System.out.println("Error clearing activity: " + result);
            }
        });
        this.core.close();
    }
}