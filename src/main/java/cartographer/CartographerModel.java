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

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.Swing;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

import java.awt.Color;

import docking.widgets.table.*;

/**
 * Table model for the Code Coverage window.
 */
public class CartographerModel extends AddressBasedTableModel<TableRowObject> {

    private transient CartographerPlugin plugin;

    /**
     * Constructor for the table model.
     * 
     * @param plugin  Main plugin object
     */
    public CartographerModel(CartographerPlugin plugin) {
        super("Code Coverage", plugin.getTool(), null, null);
        this.plugin = plugin;
    }
    
    /**
     * Copy constructor for a table model.
     * 
     * @param model  Existing CartographerModel object to copy
     */
    public CartographerModel(CartographerModel model) {
       this(model.plugin);
    }

    @Override
    protected TableColumnDescriptor<TableRowObject> createTableColumnDescriptor() {
        TableColumnDescriptor<TableRowObject> descriptor = new TableColumnDescriptor<>();

        // All visible columns within the table
        descriptor.addVisibleColumn(new CoveragePercentColumn());
        descriptor.addVisibleColumn(new FunctionNameColumn());
        descriptor.addVisibleColumn(new FunctionAddressColumn(), 0, true);  // Default column
        descriptor.addVisibleColumn(new BlocksHitColumn());
        descriptor.addVisibleColumn(new InstructionsHitColumn());
        descriptor.addVisibleColumn(new FunctionSizeColumn());

        return descriptor;
    }

    @Override
    protected void doLoad(Accumulator<TableRowObject> accumulator, TaskMonitor monitor)
            throws CancelledException {

        // Get the selected file
        CartographerProvider provider = plugin.getProvider();
        if (provider == null) {
            return;
        }
        CoverageFile file = provider.getSelectedFile();

        // Bail if no file was loaded yet
        if (file == null) {
            return;
        }

        // Bail if no function mappings exist
        if (file.getCoverageFunctions().isEmpty()) {
            return;
        }

        // Initialize the monitor
        monitor.setCancelEnabled(true);
        monitor.initialize(file.getCoverageFunctions().size());

        // Allow UI updates
        Swing.allowSwingToProcessEvents();

        // Process each code coverage function
        file.getCoverageFunctions().forEach((function, ccFunc) -> {

            // Only process if needed
            if (!ccFunc.isProcessed()) {
                ccFunc.process();
            }

            // Create a table row from the code coverage function
            TableRowObject row = new TableRowObject(ccFunc);

            // Set the background colors as the table is updating
            // (this prevents a flash of uncolored table rows)
            row.setBGColors(
                provider.getHighCoverageColor(),
                provider.getLowCoverageColor(),
                provider.getNoCoverageColor()
            );

            // Add the row to the table
            accumulator.add(row);
            monitor.incrementProgress(1);
        });
    }

    /**
     * Adds a function to the table model.
     * 
     * @param ccFunc   CoverageFunction to process
     * @param monitor  Monitor for the task
     */
    public void add(CoverageFunction ccFunc, TaskMonitor monitor) {
        TableRowObject row = new TableRowObject(ccFunc);
        row.setBGColors(Color.black, Color.black, Color.black);
        addObject(row);
    }

    /**
     * Gets the address associated with the selected row.
     * 
     * @param row  Table row that was selected
     * 
     * @return     Address (entry point) of the selected function
     */
    @Override
    public Address getAddress(int row) {
        return getRowObject(row).getFunctionAddress();
    }

//==================================================================================================
// Code Coverage Window Columns
//==================================================================================================

    /**
     * Column showing the total percentage of the function that was executed.
     */
    private class CoveragePercentColumn extends
            AbstractDynamicTableColumn<TableRowObject, Double, Object> {

        @Override
        public String getColumnName() {
            return "Coverage %";
        }

        @Override
        public Double getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return rowObject.getCoveragePercent();
        }
    }

    /**
     * Column showing the name of the function.
     */
    private class FunctionNameColumn extends
            AbstractDynamicTableColumn<TableRowObject, String, Object> {

        @Override
        public String getColumnName() {
            return "Name";
        }

        @Override
        public String getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return rowObject.getFunctionName();
        }
    }

    /**
     * Column showing the address of the function.
     */
    private class FunctionAddressColumn extends
            AbstractDynamicTableColumn<TableRowObject, String, Object> {

        @Override
        public String getColumnName() {
            return "Address";
        }

        @Override
        public String getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return String.format("0x%08X", rowObject.getFunctionAddress().getUnsignedOffset());
        }
    }

    /**
     * Column showing the number of blocks hit within the function.
     */
    private class BlocksHitColumn extends
            AbstractDynamicTableColumn<TableRowObject, String, Object> {

        @Override
        public String getColumnName() {
            return "Blocks Hit";
        }

        @Override
        public String getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return String.format("%d / %d", rowObject.getBlocksHit(), rowObject.getTotalBlocks());
        }
    }

    /**
     * Column showing the number of instructions hit within the function.
     */
    private class InstructionsHitColumn extends
            AbstractDynamicTableColumn<TableRowObject, String, Object> {

        @Override
        public String getColumnName() {
            return "Instructions Hit";
        }

        @Override
        public String getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return String.format("%d / %d", rowObject.getInstructionsHit(), rowObject.getTotalInstructions());
        }
    }

    /**
     * Column showing the size of the function in bytes.
     */
    private class FunctionSizeColumn extends
            AbstractDynamicTableColumn<TableRowObject, Long, Object> {

        @Override
        public String getColumnName() {
            return "Function Size";
        }

        @Override
        public Long getValue(TableRowObject rowObject, Settings settings, Object data,
                ServiceProvider services) throws IllegalArgumentException {
            return rowObject.getFunctionSize();
        }
    }
}
