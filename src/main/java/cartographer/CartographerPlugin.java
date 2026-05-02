/* ###
 * Cartographer
 * Copyright (C) 2023 NCC Group
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cartographer;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.MiscellaneousPluginPackage;
import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JOptionPane;
import cartographer.CoverageFile.*;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = MiscellaneousPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Code coverage parser",
    description = "Plugin for loading and processing code coverage data."
)
//@formatter:on

/**
 * Plugin for evaluating code coverage within a given executable.
 */
public class CartographerPlugin extends ProgramPlugin {

    private boolean loaded;                           // Whether code coverage has been loaded
    private ProgramLocation curLocation;              // Current location within the program
    private CartographerProvider provider;            // Code coverage provider
    private DecompilerHighlighter decompilerHighlighter; // Decompiler background highlighter

    // Name of the DockingAction group
    private static final String TOOL_GROUP_NAME = "Code Coverage";
    private static final String TOOL_GROUP_ID = "covgroup";
    private static final String DECOMPILER_HIGHLIGHTER_ID = "cartographer.coverage.decompiler";

    // List of address spaces so it's not fetched every time
    private static Map<String, AddressSpace> addressSpaceMap = new HashMap<>();

    // Loaded code coverage files
    private static Map<Integer, CoverageFile> loadedFiles = new HashMap<>();

    // Name of preference group for better file loading
    private static final String LAST_IMPORT_CODE_COVERAGE_DIRECTORY = "LastImportCodeCoverageDirectory";

    /**
     * Constructor for the plugin.
     *
     * @param tool  Tool where the plugin will be added
     */
    public CartographerPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {

        // Add the provider to the tool
        provider = new CartographerProvider(this);
        createActions();

        // Clear the loaded flag
        loaded = false;

        // Register a decompiler background highlighter using the official highlight service.
        // The service calls back into the matcher for every token whenever a function is
        // decompiled, so we do not need to intercept the DecompilerController callback
        // handler (which became final in Ghidra 11.2+).
        DecompilerHighlightService highlightService =
            tool.getService(DecompilerHighlightService.class);
        if (highlightService != null) {
            decompilerHighlighter = highlightService.createHighlighter(
                DECOMPILER_HIGHLIGHTER_ID,
                new CTokenHighlightMatcher() {

                    // Pre-built set of covered addresses for the current decompile pass.
                    private AddressSetView coveredSet = new AddressSet();

                    // Rebuild the covered-address set at the start of each decompile pass so
                    // that getTokenHighlight() lookups are O(log n) instead of O(blocks).
                    @Override
                    public void start(ghidra.app.decompiler.ClangNode root) {
                        AddressSet set = new AddressSet();
                        if (loaded && provider.getSelectedFile() != null) {
                            provider.getSelectedFile()
                                    .getCoverageFunctions()
                                    .forEach((fn, ccFunc) -> {
                                        for (CodeBlock block : ccFunc.getBlocksHit()) {
                                            set.add(block);
                                        }
                                    });
                        }
                        coveredSet = set;
                    }

                    @Override
                    public Color getTokenHighlight(ClangToken token) {
                        Address addr = token.getMinAddress();
                        if (addr == null || coveredSet.isEmpty()) {
                            return null;
                        }
                        return coveredSet.contains(addr) ? provider.getDecompilerColor() : null;
                    }
                }
            );
        }
    }

    /**
     * Creates the actions for the tool.
     */
    private void createActions() {

        // Docking action for the code coverage plugin
        DockingAction coverageAction = new DockingAction("Open CC File", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {

                // Create a file chooser
                GhidraFileChooser chooser = new GhidraFileChooser(tool.getActiveWindow());

                // Set file chooser settings
                chooser.setTitle("Select Code Coverage File(s)");
                chooser.setApproveButtonText("Open");
                chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
                chooser.setMultiSelectionEnabled(true);

                // Get the last opened code coverage directory
                String ccDir = Preferences.getProperty(LAST_IMPORT_CODE_COVERAGE_DIRECTORY);

                // Open the last directory if one exists
                if (ccDir != null) {
                    chooser.setCurrentDirectory(new File(ccDir));
                }

                // Get the selected file(s)
                List<File> selectedFiles = chooser.getSelectedFiles();

                // Bail if selection was canceled
                if (chooser.wasCancelled()) {
                    return;
                }

                // Update the previous opened directory
                Preferences.setProperty(LAST_IMPORT_CODE_COVERAGE_DIRECTORY, selectedFiles.get(0).getAbsolutePath());

                // Populate the address space map
                AddressSpace[] spaces = currentProgram.getAddressFactory().getAddressSpaces();
                for (AddressSpace space : spaces) {
                    addressSpaceMap.put(space.getName(), space);
                }

                // Process each selected file
                selectedFiles.forEach(selected -> {

                    // Load the code coverage file
                    CoverageFile file = null;
                    try {
                        file = new CoverageFile(selected.getAbsolutePath());
                    }
                    catch (IOException e) {
                        throw new AssertionError(e.getMessage());
                    }

                    // Attempt to process the code coverage file
                    if (!processCoverageFile(file)) {
                    	return;
                    }
                });
            }
        };

        // Enable the action
        coverageAction.setEnabled(true);

        // Make it selectable in the "Tools" menu
        coverageAction.setMenuBarData(new MenuData(
            new String[] {                      // Menu Path
                ToolConstants.MENU_TOOLS,
                TOOL_GROUP_NAME,
                "Load Code Coverage File(s)..."
            },
            null,                               // Icon
            TOOL_GROUP_ID,                      // Menu Group
            MenuData.NO_MNEMONIC,               // Mnemonic
            "1"                                 // Menu Subgroup
        ));

        // Add the action to the tool
        tool.addAction(coverageAction);
    }

    /**
     * Re-applies decompiler highlights for the currently selected coverage file.
     * <p>
     * Call this whenever the selected file or the decompiler highlight color changes.
     * The registered {@link DecompilerHighlighter} will invoke our
     * {@link CTokenHighlightMatcher}, which re-builds the covered-address set from
     * the current coverage data and colors each matching token.
     * </p>
     */
    public void colorizeDecompiler() {
        if (decompilerHighlighter != null) {
            decompilerHighlighter.applyHighlights();
        }
    }

    /**
     * Colorizes the lines in the listing (disassembly) view.
     *
     * @param file  Coverage file to be processed
     */
    public void colorizeListing(CoverageFile file) {

        // Get the colorizer
        ColorizingService colorizer = tool.getService(ColorizingService.class);

        // Clear out the current highlights
        int transactionId = currentProgram.startTransaction("Clearing Listing Data Highlights");
        colorizer.clearAllBackgroundColors();

        // Set background color for each block
        file.getCoverageFunctions().forEach((function, ccFunc) -> {

            for (CodeBlock block : ccFunc.getBlocksHit()) {
                colorizer.setBackgroundColor(block, provider.getListingColor());
            }
        });

        // End the transaction
        currentProgram.endTransaction(transactionId, true);

        // Re-apply decompiler highlights with the updated coverage data
        colorizeDecompiler();
    }

    /**
     * Loads the given code coverage file.
     *
     * @param file  Coverage file to load
     *
     * @return      True if successfully loaded coverage file, false if not
     */
    public boolean loadCoverageFile(CoverageFile file) {

        // Clear out function map
        file.clearCoverageFunctions();

        // Allow UI updates
        Swing.allowSwingToProcessEvents();

        // Populate the function map
        FunctionIterator fnIter = currentProgram.getFunctionManager().getFunctions(true);
        while (fnIter.hasNext()) {
            Function curFunc = fnIter.next();
            CoverageFunction ccFunc = new CoverageFunction(curFunc);
            file.addCoverageFunction(curFunc, ccFunc);
            provider.add(ccFunc);
        }

        // Set default previous function address (kept for compatibility)
        currentProgram.getListing()
                .getDefaultRootModule()
                .getMinAddress()
                .getAddressSpace()
                .getMinAddress();

        // Check if this was a DrCov file
        if (file.getType().equals("drcov")) {

            // Create a list of modules to select from
            List<String> modNames = new ArrayList<>();
            for (String modName : file.getModules().keySet()) {
                modNames.add(modName);
            }

            // Ask the user which module to use
            String response = (String)JOptionPane.showInputDialog(
                null,
                "Please select the code coverage module to use.",
                "Select a Coverage Module",
                JOptionPane.QUESTION_MESSAGE,
                null,
                modNames.toArray(),
                modNames.get(0)
            );

            // Bail if no option was chosen
            if (response == null) {
                return false;
            }

            // Get the module data from the selected module option
            DrCovModule module = file.getModule(response);

            // Set the file blocks
            file.setBlocks(module.getBasicBlocks());
        }

        else if (file.getType().equals("ezcov")) {
            // No processing needed for EZCOV files
        }

        // Unsupported type
        else {
            Utils.showError(
                file.getStatusCode().toString(),
                file.getStatusMessage()
            );
            return false;
        }

        // Populate the coverage function blocks
        file.populateBlocks(currentProgram);

        // Apply decompiler highlights for the newly loaded coverage data
        colorizeDecompiler();

        return true;
    }

    /**
     * Processes the given code coverage file.
     *
     * @param file  Coverage file to process
     *
     * @return      Whether or not the coverage file was successfully processed
     */
    public boolean processCoverageFile(CoverageFile file) {

    	// Only process if no errors were encountered
        if (file.getStatusCode() != CoverageFile.STATUS.OK) {
            Utils.showError(
                file.getStatusCode().toString(),
                file.getStatusMessage()
            );
            return false;
        }

        // Load the coverage file data
        if (!loadCoverageFile(file)) {
            return false;
        }

        // Set the selected file for the provider
        provider.setSelectedFile(file);

        // Set to loaded
        loaded = true;

        // Reload the model
        provider.setFileLoadedFlag();
        provider.getModel().reload();

        // Associate the model with the file
        file.setModel(provider.getModel());

        // Give the loaded file a unique ID
        file.setId(loadedFiles.size());
        file.setAlphaId(Utils.idToAlpha(loadedFiles.size()));

        // Add the file data to the list of loaded files
        loadedFiles.put(file.getId(), file);

        // Successfully processed
        return true;
    }

    /**
     * Gets the provider for the plugin.
     *
     * @return  Plugin provider
     */
    public CartographerProvider getProvider() {
        return provider;
    }

    @Override
    protected void locationChanged(ProgramLocation location) {

        // Just set the current location
        curLocation = location;
    }

    /**
     * Make sure no remnant data exists between CodeBrowser launches.
     */
    @Override
    protected void dispose() {
        super.dispose();
        if (decompilerHighlighter != null) {
            decompilerHighlighter.dispose();
            decompilerHighlighter = null;
        }
        provider.dispose();
    }

    /**
     * Gets an address space by its name.
     *
     * @param addressSpaceName  Name of the address space
     *
     * @return                  Address space associated with the given name
     */
    public static AddressSpace getAddressSpace(String addressSpaceName) {
        return addressSpaceMap.get(addressSpaceName);
    }

    /**
     * Gets the list of currently-loaded files.
     *
     * @return  Hashmap of loaded files
     */
    public static Map<Integer, CoverageFile> getLoadedFiles() {
        return loadedFiles;
    }
}
