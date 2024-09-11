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
import docking.widgets.DataToStringConverter;
import docking.widgets.ListSelectionDialog;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.decompiler.component.ClangLayoutController;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.decompiler.component.DecompilerCallbackHandler;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Swing;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import utility.function.Callback;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.test.TestUtils;
import ghidra.program.model.block.*;
import ghidra.MiscellaneousPluginPackage;
import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    private Address prevFunctionAddress;                // Previous location
    private FieldPanel fieldPanel;                      // Decompiler field panel
    private ClangLayoutController layoutController;     // Decompiler panel layout controller
    private boolean loaded;                             // Whether code coverage has been loaded
    private boolean updating;                           // Whether decompiler is updating
    private DecompilerCallbackHandler callbackHandler;  // Generic decompiler callback handler
    private ProgramLocation curLocation;                // Current location within the program
    private CartographerProvider provider;              // Code coverage provider

    // Name of the DockingAction group
    private static final String TOOL_GROUP_NAME = "Code Coverage";
    private static final String TOOL_GROUP_ID = "covgroup";

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

        // Get the decompiler service from the current tool
        DecompilerProvider decompilerService = (DecompilerProvider)tool.getService(DecompilerHighlightService.class);

        // Get the decompiler controller from the service
        DecompilerController controller = decompilerService.getController();

        // Get the decompiler panel
        DecompilerPanel decompilerPanel = controller.getDecompilerPanel();

        // Get the field panel
        fieldPanel = decompilerPanel.getFieldPanel();

        // Get the layout controller
        layoutController = decompilerPanel.getLayoutController();

        // Set the initial highlight color for decompiler highlights
        fieldPanel.setHighlightColor(provider.getDecompilerColor());

        // Clear the loaded flag
        loaded = false;

        // Clear the update flag
        updating = false;

        // Get the existing callback handler for the decompiler controller
        callbackHandler = (DecompilerCallbackHandler)TestUtils.getInstanceField("callbackHandler", controller);

        // Set the callback handler of the decompiler controller
        TestUtils.setInstanceField("callbackHandler", controller, new DecompilerCallbackHandler() {

            // Set to trigger when decompilation data changes
            @Override
            public void decompileDataChanged(DecompileData decompileData) {

                // Bail if currently updating
                if (updating) {
                    return;
                }

                // Set updating flag
                updating = true;

                // Only process if decompilation data exists
                if (decompileData != null) {

                    // Get result of the decompilation
                    DecompileResults results = decompileData.getDecompileResults();

                    // Only process if decompilation results were collected and were fully completed
                    if (results != null && results.decompileCompleted()) {

                        // Get the current high function
                        HighFunction hf = decompileData.getHighFunction();

                        // Colorize the data in the Decompiler window
                        if (hf != null) {
                            colorizeDecompilerAfterViewUpdate();
                        }
                    }
                }

                // Clear updating flag
                updating = false;

                // Flag that the decompilation data has changed to the callback handler
                callbackHandler.decompileDataChanged(decompileData);
            }

            // Do all the other required things
            @Override
            public void contextChanged() {
                callbackHandler.contextChanged();
            }

            @Override
            public void setStatusMessage(String message) {
                callbackHandler.setStatusMessage(message);
            }

            @Override
            public void locationChanged(ProgramLocation programLocation) {
                callbackHandler.locationChanged(programLocation);
            }

            @Override
            public void selectionChanged(ProgramSelection programSelection) {
                callbackHandler.selectionChanged(programSelection);
            }

            @Override
            public void annotationClicked(AnnotatedTextFieldElement annotation, boolean newWindow) {
                callbackHandler.annotationClicked(annotation, newWindow);
            }

            @Override
            public void goToLabel(String labelName, boolean newWindow) {
                callbackHandler.goToLabel(labelName, newWindow);
            }

            @Override
            public void goToAddress(Address addr, boolean newWindow) {
                callbackHandler.goToAddress(addr, newWindow);
            }

            @Override
            public void goToScalar(long value, boolean newWindow) {
                callbackHandler.goToScalar(value, newWindow);
            }

            @Override
            public void exportLocation() {
                callbackHandler.exportLocation();
            }

            @Override
            public void goToFunction(Function function, boolean newWindow) {
                callbackHandler.goToFunction(function, newWindow);
            }

            @Override
            public void doWhenNotBusy(Callback c) {
                callbackHandler.doWhenNotBusy(c);
            }

        });
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
     * Calls the decompiler colorizer for the current decompiler view.
     * <p>
     * Note: This is only called when changing the Decompiler highlight color.
     * </p>
     */
    public void colorizeDecompiler() {

        // Get the current address in the program
        Address currentAddress = curLocation.getAddress();

        // Get the function containing the address
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);

        // Only run if current function exists under the cursor
        if (currentFunction != null) {

            // Get the current function's code coverage data
            CoverageFunction ccFunc = provider.getSelectedFile().getCoverageFunction(currentFunction);

            // Update the decompiler highlights for the current function
            colorizeDecompiler(ccFunc);

        }
    }

    /**
     * Colorizes the decompiler view for the selected function.
     * 
     * @param ccFunc  Code coverage data for the current function
     */
    private void colorizeDecompiler(CoverageFunction ccFunc) {

        // Allocate a new selection
        FieldSelection selection = new FieldSelection();

        // Reset the highlights
        fieldPanel.clearHighlight();

        // Loop through each block that was hit
        for (CodeBlock block : ccFunc.getBlocksHit()) {

            // Get the decompiler tokens and associated selection range
            List<ClangToken> tokens = DecompilerUtils.getTokens(layoutController.getRoot(), block);
            FieldSelection subSelection = DecompilerUtils.getFieldSelection(tokens);

            // Add each decompiler hit range to be highlighted
            for (int i = 0; i < subSelection.getNumRanges(); i++) {
                selection.addRange(DecompilerUtils.getFieldSelection(tokens).getFieldRange(i));
            }
        }

        // Highlight the selections
        fieldPanel.setHighlight(selection);
    }

    /**
     * Calls the decompiler colorizer after a Decompiler view update.
     */
    public void colorizeDecompilerAfterViewUpdate() {

        // Bail if not loaded
        if (!loaded) {
            return;
        }

        // Bail if function yeeted
        if (currentProgram == null) {
            return;
        }

        // Get the current function
        Function curFunction = currentProgram.getFunctionManager().getFunctionContaining(curLocation.getAddress());
        if (curFunction == null) {
            return;
        }

        // Get the address of the current function
        Address curFunctionAddress = curFunction.getEntryPoint();

        // Only do thing if function changed
        if (curFunctionAddress.equals(prevFunctionAddress)) {
            return;
        }

        // Update the decompiler highlights for the current function
        CoverageFunction ccFunc = provider.getSelectedFile().getCoverageFunction(curFunction);

        // Make sure the function exists
        if (ccFunc != null) {

            // Update the decompiler highlights for the current function
            colorizeDecompiler(ccFunc);
        }

        // Update previous location
        prevFunctionAddress = curFunctionAddress;
    }

    /**
     * Colorizes the lines in the listing (disassembly) view.
     * 
     * @param file  Coverage file to be processed
     */
    public void colorizeListing(CoverageFile file) {

        // Get the current address in the program
        Address currentAddress = curLocation.getAddress();

        // Get the function containing the address
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);

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

        // Only run if current function exists under the cursor
        if (currentFunction != null) {

            // Update the decompiler highlights for the current function
            CoverageFunction ccFunc = file.getCoverageFunction(currentFunction);
            colorizeDecompiler(ccFunc);
        }

        // End the transaction
        currentProgram.endTransaction(transactionId, true);
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

        // Get the current address in the program
        Address currentAddress = curLocation.getAddress();

        // Set default previous function address
        prevFunctionAddress = currentProgram.getListing()
                .getDefaultRootModule()
                .getMinAddress()
                .getAddressSpace()
                .getMinAddress();

        // Get the function containing the current address
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);

        // Check if this was a DrCov file
        if (file.getType().equals("drcov")) {

            // Create a list of modules to select from
            List<String> modNames = new ArrayList<>();
            for (String modName : file.getModules().keySet()) {
                modNames.add(modName);
            }

            // Ask the user which module to use
            ListSelectionDialog<String> responseDialog = new ListSelectionDialog<String>(
                "Select a Coverage Module", 
                "Module", 
                modNames, 
                DataToStringConverter.stringDataToStringConverter);

            responseDialog.show(tool.getActiveWindow());
            String response = responseDialog.getSelectedItem();

            if (responseDialog.wasCancelled()) {
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

        // Only run if current function exists under the cursor
        if (currentFunction != null) {

            // Get the current function's code coverage data
            CoverageFunction ccFunc = file.getCoverageFunction(currentFunction);

            // Update the decompiler highlights for the current function
            colorizeDecompiler(ccFunc);

        }

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

    /**
     * Sets the highlight color for the Decompiler view.
     * 
     * @param color  Color to use for decompilation highlighting
     */
    public void setDecompilerHighlightColor(Color color) {
        fieldPanel.setHighlightColor(color);
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
