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

import java.awt.*;
import java.awt.event.ItemEvent;
import javax.swing.*;
import docking.ActionContext;
import docking.action.*;
import docking.widgets.label.GDLabel;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.threaded.ThreadedTableModelListener;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.*;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.task.TaskMonitor;

/**
 * Provider for the Cartographer plugin.
 */
public class CartographerProvider extends ComponentProviderAdapter implements OptionsChangeListener {

    // Name of the options group
    private static final String OPTIONS_TITLE = "Code Coverage";

    // Listing coverage color (blue-ish by default)
    private static final String LISTING_COVERAGE_COLOR_OPTION_NAME = "Assembly Highlight Color";
    private static final String LISTING_COVERAGE_COLOR_OPTION_DESC = (
        "Color to use for highlighting overall coverage within the Listing window."
    );

    // Decompiler coverage color (blue-ish by default)
    private static final String DECOMPILER_COVERAGE_COLOR_OPTION_NAME = "Decompiler Highlight Color";
    private static final String DECOMPILER_COVERAGE_COLOR_OPTION_DESC = (
        "Color to use for highlighting coverage within the Decompiler window."
    );

    // Whether to display high contrast text in the coverage window
    private static final String DISPLAY_HIGH_CONTRAST_TEXT_OPTION_NAME = "Display High Contrast Text";
    private static final String DISPLAY_HIGH_CONTRAST_TEXT_OPTION_DESC = (
        "When enabled, the row text shown in the Code Coverage window " +
        "will automatically adjust itself based on the background color."
    );

    // Whether to show colorized highlights
    private static final String SHOW_ROW_HIGHLIGHTS_OPTION_NAME = "Enable Colorized Tables";
    private static final String SHOW_ROW_HIGHLIGHTS_OPTION_DESC = (
        "When enabled, the rows shown in the Code Coverage window " +
        "will be colorized based on the function's coverage percentage."
    );

    // High coverage color (blue by default)
    private static final String HIGH_COVERAGE_COLOR_OPTION_NAME = "High Coverage Color";
    private static final String HIGH_COVERAGE_COLOR_OPTION_DESC = (
        "Color to use when highlighting functions with high coverage."
    );

    // Low coverage color (red by default)
    private static final String LOW_COVERAGE_COLOR_OPTION_NAME = "Low Coverage Color";
    private static final String LOW_COVERAGE_COLOR_OPTION_DESC = (
        "Color to use when highlighting functions with low coverage."
    );

    // No coverage color (dark grey by default)
    private static final String NO_COVERAGE_COLOR_OPTION_NAME = "No Coverage Color";
    private static final String NO_COVERAGE_COLOR_OPTION_DESC = (
        "Color to use when highlighting functions that don't have any coverage."
    );

    // Option values
    private Color decompilerCoverageColor = new GColor("color.bg.plugin.overview.cartographer.decompiler");
    private Color listingCoverageColor = new GColor("color.bg.plugin.overview.cartographer.listing");
    private boolean showRowHighlights = true;
    private boolean displayHighContrastText = true;
    private Color highCoverageColor = new GColor("color.bg.plugin.overview.cartographer.high");
    private Color lowCoverageColor = new GColor("color.bg.plugin.overview.cartographer.low");
    private Color noCoverageColor = new GColor("color.bg.plugin.overview.cartographer.none");

    private CartographerPlugin plugin;                  // Main plugin

    private JComponent component;                       // Wrapper component for the tool window
    private JPanel mainPanel;                           // Main panel within the component
    private JComboBox<CoverageFile> fileSelector;       // Coverage file dropdown selector
    private GFilterTable<TableRowObject> filterTable;   // Filterable table of function coverage
    private GTable dataTable;                           // Table data of filterTable
    private CartographerModel model;                    // Model to use for the table

    private boolean modelProcessed;                     // Whether the model needs to be processed
    private boolean fileLoaded;                         // Whether a new file has just been loaded

    private CoverageFile selectedFile;                  // Currently-selected coverage file

    private CoverageFile expressionResult;              // Result of a coverage expression

    /**
     * Constructor for the provider of the plugin.
     * 
     * @param plugin  Main plugin object
     */
    public CartographerProvider(CartographerPlugin plugin) {
        super(plugin.getTool(), OPTIONS_TITLE, plugin.getName());
        setIcon(new GIcon("icon.cartographer.plugin.action.window"));
        setKeyBinding(new KeyBindingData("Ctrl-Shift-C"));
        this.plugin = plugin;

        // Create the initial model and build the component
        modelProcessed = false;
        component = build();
        createActions();
        initializeOptions();
        addToTool();
    }

    /**
     * Disposes of the table and remove the provider from the tool.
     */
    void dispose() {
        filterTable.dispose();
        CartographerPlugin.getLoadedFiles().clear();
        removeFromTool();
    }

    /**
     * Builds the component view.
     * 
     * @return  Outer component for the Code Coverage window
     */
    private JComponent build() {

        JPanel panel = new JPanel(new BorderLayout());

        panel.add(buildTablePanel());

        return panel;
    }

    /**
     * Builds the main table and associated controls.
     * 
     * @return  JPanel component containing the function table and controls
     */
    private Component buildTablePanel() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        // Create the initial model
        createModel();

        // Regenerate the filter table
        regenerateTable();

        // Generic listener to update subtitle text showing the number of items currently being shown
        model.addTableModelListener(e -> {
            int rowCount = model.getRowCount();
            int unfilteredCount = model.getUnfilteredRowCount();

            setSubTitle("" + rowCount + " functions" +
                (rowCount != unfilteredCount ? " (of " + unfilteredCount + ")" : ""));
        });

        // Add a threaded listener to update the UI
        model.addThreadedTableModelListener(new ThreadedTableModelListener() {

            @Override
            public void loadingStarted() {
                // Ignore load start events
            }

            @Override
            public void loadingFinished(boolean wasCancelled) {

                // Only process if the model has been fully loaded
                if (model.getRowCount() != 0 && fileLoaded) {

                    // Repopulate the dropdown if this wasn't an expression result
                    if (!selectedFile.getAlphaId().equals("$")) {

                        // Populate file selector with all currently-loaded files
                        fileSelector.removeAllItems();
                        CartographerPlugin.getLoadedFiles().forEach(
                            (id, file) -> fileSelector.addItem(file)
                        );

                        // Reset dropdown process flag
                        fileSelector.setSelectedItem(selectedFile);
                    }

                    // Repaint the UI
                    updateAndRepaint();

                    // Clear flag
                    fileLoaded = false;
                    modelProcessed = true;

                    // Clone the model for fast reloading
                    selectedFile.setModel(new CartographerModel(model));
                }
            }

            @Override
            public void loadPending() {
                // Ignore load pending events
            }
        });

        // Add the coverage table to the list
        mainPanel.add(filterTable);

        // Create a panel for spacing below the filter area
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));

        // Create bottom control components
        fileSelector = new JComboBox<>();

        // Set maximum size to 200px width
        fileSelector.setPreferredSize(new Dimension(200, 25));

        // Create a panel for the bottom controls
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new BoxLayout(controlPanel, BoxLayout.X_AXIS));

        GDLabel expressionLabel = new GDLabel("Expression:");
        expressionLabel.setToolTipText("Evaluate expressions here.");

        GDLabel modelLabel = new GDLabel("Model:");
        modelLabel.setToolTipText("The coverage model to display.");

        JTextField expressionText = new JTextField();
        expressionText.setName("expression.textfield");

        // Update the table and colorization whenever a module is selected from the dropdown
        fileSelector.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED && modelProcessed && !fileLoaded) {

                // Update the selected file (model is automatically processed)
                selectedFile = (CoverageFile)e.getItem();

                // Swap each coverage function in the table
                selectedFile.getCoverageFunctions().forEach(
                    (function, ccFunc) -> add(ccFunc)
                );
                setFileLoadedFlag();
                model.reload();
                selectedFile.setModel(getModel());
            }
        });

        JSeparator separator = new JSeparator(SwingConstants.VERTICAL);

        // Button to execute the given expression
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {

            // Get the expression text
            String expr = expressionText.getText();

            // Create and reset the tokenizer
            ExpressionTokenizer.Tokenizer tokenizer = new ExpressionTokenizer.Tokenizer(expr);
            tokenizer.reset();

            // Evaluate the expression into a new file
            expressionResult = new ExpressionTokenizer.Evaluator(tokenizer, CartographerPlugin.getLoadedFiles()).evaluate();

            // Recreate the model if the expression was successfully parsed
            if (expressionResult != null) {

                expressionResult.getCoverageFunctions().forEach(
                    (function, ccFunc) -> add(ccFunc)
                );
                setSelectedFile(expressionResult);
                setFileLoadedFlag();
                model.reload();
                expressionResult.setModel(getModel());
                
                // Set the result's ID
                expressionResult.setAlphaId("$");
            }
        });

        // Add control components with even spacing
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(expressionLabel);
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(expressionText);
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(applyButton);
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(separator);
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(modelLabel);
        controlPanel.add(Box.createHorizontalStrut(5));
        controlPanel.add(fileSelector);

        // Add the control components to the bottom panel
        bottomPanel.add(Box.createVerticalStrut(5));
        bottomPanel.add(controlPanel);
        bottomPanel.add(Box.createVerticalStrut(2));

        // Add the controls to the bottom of the main layout
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        return mainPanel;
    }

    /**
     * Updates and repaints the main panel table, then colorizes the assembly.
     */
    public void updateAndRepaint() {

        // Regenerate the filter table
        mainPanel.remove(filterTable);
        regenerateTable();
        mainPanel.add(filterTable);

        // Update the listing data colorization
        if (selectedFile != null) {
            plugin.colorizeListing(selectedFile);
        }
    }

    /**
     * Regenerates the filtered table.
     */
    private void regenerateTable() {

        CartographerModel filterModel = model;
        if (selectedFile != null) {
            filterModel = selectedFile.getModel();
        }

        // Create a new filter table
        filterTable = new GFilterTable<>(filterModel);
        dataTable = filterTable.getTable();

        // Set renderer for each cell of the table
        for (int i = 0; i < dataTable.getColumnCount(); i++) {
            dataTable.getColumnModel().getColumn(i).setCellRenderer(new CodeCoverageTableCellRenderer());
        }

        // Go to the address of the selected function when a row is selected
        dataTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            // Make sure only 1 line was selected
            GoToService goToService = tool.getService(GoToService.class);
            TableRowObject row = filterTable.getSelectedRowObject();
            if (row != null) {
                goToService.goTo(row.getFunctionAddress(), plugin.getCurrentProgram());
            }
        });
    }

    /**
     * Creates the component actions.
     * <p>
     * Note: This includes buttons at the top of the component as well as the
     * options shown when right-clicking an entry.
     * </p>
     */
    private void createActions() {
        DockingAction optionsAction = new DockingAction("Code Coverage Options", plugin.getName()) {

            @Override
            public void actionPerformed(ActionContext context) {
                OptionsService service = tool.getService(OptionsService.class);
                service.showOptionsDialog(OPTIONS_TITLE, OPTIONS_TITLE);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return tool.getService(OptionsService.class) != null;
            }

        };
        Icon icon = new GIcon("icon.cartographer.plugin.action.show.options");
        optionsAction.setToolBarData(new ToolBarData(icon));
        addLocalAction(optionsAction);
    }

    @Override
    public JComponent getComponent() {
        return component;
    }

    /**
     * Gets the currently-loaded model.
     * 
     * @return  Table model currently being used
     */
    public CartographerModel getModel() {
        return model;
    }

    /**
     * Creates a new table model.
     */
    public void createModel() {
        model = new CartographerModel(plugin);
    }

    /**
     * Sets the currently-selected coverage file.
     * 
     * @param file  Loaded code coverage file to set as the selected file
     */
    public void setSelectedFile(CoverageFile file) {
        selectedFile = file;
        fileLoaded = false;
    }

    /**
     * Gets the currently-selected coverage file.
     * 
     * @return  Code coverage file currently being used for analysis
     */
    public CoverageFile getSelectedFile() {
        return selectedFile;
    }

    /**
     * Gets the color used for the Listing view.
     * 
     * @return  Color for the Listing view
     */
    public Color getListingColor() {
        return listingCoverageColor;
    }

    /**
     * Gets the color used for the Decompiler view.
     * 
     * @return  Color for the Decompiler view
     */
    public Color getDecompilerColor() {
        return decompilerCoverageColor;
    }
    
    /**
     * Gets the color used for high code coverage values.
     * 
     * @return  Color for high coverage
     */
    public Color getHighCoverageColor() {
        return highCoverageColor;
    }
    
    /**
     * Gets the color used for low code coverage values.
     * 
     * @return  Color for low coverage
     */
    public Color getLowCoverageColor() {
        return lowCoverageColor;
    }
    
    /**
     * Gets the color used for entries with no coverage.
     * 
     * @return  Color for no coverage
     */
    public Color getNoCoverageColor() {
        return noCoverageColor;
    }

    /**
     * Adds a function to the function table.
     * 
     * @param ccFunc  CoverageFunction to add to the table
     */
    public void add(CoverageFunction ccFunc) {
        if (isVisible()) {
            model.add(ccFunc, TaskMonitor.DUMMY);
        }
    }

    /**
     * Sets the fileLoaded flag to trigger a UI update.
     */
    public void setFileLoadedFlag() {
        fileLoaded = true;
    }

    /**
     * Clears the expression result so that it doesn't get auto-processed.
     */
    public void clearExpressionResult() {
        expressionResult = null;
    }

//==================================================================================================
// Table Renderer Subclass
//==================================================================================================

    /**
     * Custom table cell renderer for detailed function coverage data.
     */
    public class CodeCoverageTableCellRenderer extends AbstractGColumnRenderer<Object> {

        /**
         * Fetches the string value of an object.
         * 
         * @param value  Object to display
         * 
         * @return       String value of the object, or "???" if invalid
         */
        protected String formatString(Object value) {
            return value == null ? "???" : value.toString();
        }

        @Override
        public Component getTableCellRendererComponent(GTableCellRenderingData data) {
            super.getTableCellRendererComponent(data);

            // Limit to 2 decimal places for floats
            if (data.getValue() instanceof Double) {
                setText(String.format("%1.2f%%", data.getValue()));
            }
            else if (data.getValue() instanceof Long) {
                setText(data.getValue().toString());
            }
            else {
                setText(formatString(data.getValue()));
            }

            // Get the selected row
            TableRowObject row = (TableRowObject)data.getRowObject();
            int selectedRow = dataTable.getSelectedRow();

            // Only highlight rows if instructed to do so
            if (showRowHighlights && row.getBGColor() != null) {
                
                // Set the background color based on the coverage amount
                setBackground(row.getBGColor());
                
                // Set foreground color either to an auto-adjusted value or to white
                if (displayHighContrastText) {
                    setForeground(ColorUtils.contrastForegroundColor(row.getBGColor()));
                }
                else {
                    setForeground(Color.white);
                }

                // Handler for selected row colors
                if (selectedRow == data.getRowViewIndex()) {
                    GColor selectedColor = new GColor("color.bg.plugin.overview.cartographer.selected");
                    setBackground(selectedColor);
                    setBorder(noFocusBorder);
                    
                    // Check if foreground color should be modified
                    if (displayHighContrastText) {
                        setForeground(ColorUtils.contrastForegroundColor(selectedColor));
                    }
                }
            }

            return this;
        }

        @Override
        public String getFilterString(Object t, Settings settings) {
            return formatString(t);
        }
    }

//==================================================================================================
// Options Methods
//==================================================================================================

    /**
     * Initializes the available options for the plugin.
     */
    private void initializeOptions() {
        ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

        // Create a new help location
        HelpLocation help = new HelpLocation("CartographerPlugin", "Code_Coverage");

        // Assembly listing color
        opt.registerThemeColorBinding(
            LISTING_COVERAGE_COLOR_OPTION_NAME,
            "color.bg.plugin.overview.cartographer.listing",
            help,
            LISTING_COVERAGE_COLOR_OPTION_DESC
        );

        // Decompiler listing color
        opt.registerThemeColorBinding(
            DECOMPILER_COVERAGE_COLOR_OPTION_NAME,
            "color.bg.plugin.overview.cartographer.decompiler",
            help,
            DECOMPILER_COVERAGE_COLOR_OPTION_DESC
        );

        // High coverage color
        opt.registerThemeColorBinding(
            HIGH_COVERAGE_COLOR_OPTION_NAME,
            "color.bg.plugin.overview.cartographer.high",
            help,
            HIGH_COVERAGE_COLOR_OPTION_DESC
        );

        // Low coverage color
        opt.registerThemeColorBinding(
            LOW_COVERAGE_COLOR_OPTION_NAME,
            "color.bg.plugin.overview.cartographer.low",
            help,
            LOW_COVERAGE_COLOR_OPTION_DESC
        );

        // No coverage color
        opt.registerThemeColorBinding(
            NO_COVERAGE_COLOR_OPTION_NAME,
            "color.bg.plugin.overview.cartographer.none",
            help,
            NO_COVERAGE_COLOR_OPTION_DESC
        );

        // Show highlights
        opt.registerOption(
            SHOW_ROW_HIGHLIGHTS_OPTION_NAME,
            true,
            help,
            SHOW_ROW_HIGHLIGHTS_OPTION_DESC
        );
        showRowHighlights = opt.getBoolean(
            SHOW_ROW_HIGHLIGHTS_OPTION_NAME,
            true
        );

        // Show high-contrast text
        opt.registerOption(
            DISPLAY_HIGH_CONTRAST_TEXT_OPTION_NAME,
            true,
            help,
            DISPLAY_HIGH_CONTRAST_TEXT_OPTION_DESC
        );
        displayHighContrastText = opt.getBoolean(
                DISPLAY_HIGH_CONTRAST_TEXT_OPTION_NAME,
            true
        );

        opt.addOptionsChangeListener(this);
    }

    /**
     * Updates data depending on which options were changed.
     * 
     * @param options     Options property being changed
     * @param optionName  Name of the option being changed
     * @param oldValue    Old option value
     * @param newValue    New option value
     */
    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
        
        // Check if this was one of the checkbox options
        if (newValue instanceof Boolean flag) {
            
            // Update high-contrast text option
            if (DISPLAY_HIGH_CONTRAST_TEXT_OPTION_NAME.equals(optionName)) {
                displayHighContrastText = flag;
            }

            // Update row highlight option
            else if (SHOW_ROW_HIGHLIGHTS_OPTION_NAME.equals(optionName)) {
                showRowHighlights = flag;
            }
        }

        // Default to no colors being changed
        boolean colorsChanged = false;

        // Check if this was a color-based option
        if (newValue instanceof Color color) {
            
            // Check which option was selected
            switch (optionName) {
                case LISTING_COVERAGE_COLOR_OPTION_NAME:
                    listingCoverageColor = color;
                    plugin.colorizeListing(selectedFile);
                    break;
                case DECOMPILER_COVERAGE_COLOR_OPTION_NAME:
                    decompilerCoverageColor = color;
                    plugin.colorizeDecompiler();
                    break;
                case HIGH_COVERAGE_COLOR_OPTION_NAME:
                    highCoverageColor = color;
                    colorsChanged = true;
                    break;
                case LOW_COVERAGE_COLOR_OPTION_NAME:
                    lowCoverageColor = color;
                    colorsChanged = true;
                    break;
                case NO_COVERAGE_COLOR_OPTION_NAME:
                    noCoverageColor = color;
                    colorsChanged = true;
                    break;
                default:
                    break;
            }
        }

        // Update any colors
        if (colorsChanged) {
            for (int i = 0; i < dataTable.getRowCount(); i++) {
                TableRowObject row = selectedFile.getModel().getRowObject(i);
                row.setBGColors(highCoverageColor, lowCoverageColor, noCoverageColor);
            }
        }
    }
}
