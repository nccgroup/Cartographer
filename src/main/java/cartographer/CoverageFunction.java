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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a function with populated code coverage data.
 */
public class CoverageFunction {

    private Function function;
    private Address entryPoint;
    private Map<Address, Integer> ccBlockEntries;
    private long totalBlocks;
    private long totalInstructions;
    private List<CodeBlock> blocksHit;
    private long instructionsHit;
    private long functionSize;
    private boolean processed;

    /**
     * Constructor for a code coverage function.
     * 
     * @param fn  Ghidra function
     */
    public CoverageFunction(Function fn) {

        function = fn;
        entryPoint = fn.getEntryPoint();
        ccBlockEntries = new HashMap<>();
        functionSize = fn.getBody().getNumAddresses();
        totalBlocks = 0;
        totalInstructions = 0;
        blocksHit = new ArrayList<>();
        instructionsHit = 0;

        // Ensure initial processing occurs
        processed = false;
    }
    
    /**
     * Copy constructor for code coverage functions.
     * 
     * @param ccFunc  Existing CoverageFunction object to copy
     */
    public CoverageFunction(CoverageFunction ccFunc) {
        function = ccFunc.function;
        entryPoint = ccFunc.entryPoint;
        ccBlockEntries = new HashMap<>();
        functionSize = ccFunc.functionSize;
        totalBlocks = ccFunc.totalBlocks;
        totalInstructions = ccFunc.totalInstructions;
        blocksHit = new ArrayList<>();
        instructionsHit = ccFunc.instructionsHit;
        
        // Don't do any processing on copied objects
        processed = true;
        
        // Populate the coverage block entries
        ccFunc.ccBlockEntries.forEach(
            (offset, size) -> ccBlockEntries.put(offset, size)
        );
        
        // Populate the blocks hit
        for (int i = 0; i < ccFunc.blocksHit.size(); i++) {
            this.blocksHit.add(ccFunc.blocksHit.get(i));
        }
    }

    /**
     * Processes each function block and populates coverage data.
     */
    public void process() {

        // Reset code coverage counts
        totalBlocks = 0;
        blocksHit.clear();
        totalInstructions = 0;
        instructionsHit = 0;

        Program fnProgram = function.getProgram();
        CodeBlockModel blockModel = new SimpleBlockModel(fnProgram);

        AddressSetView body = function.getBody();

        // Get the total number of blocks for this function
        CodeBlockIterator fnBlocks;
        try {
            fnBlocks = blockModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);
        }
        catch (CancelledException e) {
            return;
        }

        // Loop through each function block
        fnBlocks.forEach(block -> {

            // Increment the block counter
            totalBlocks += 1;

            // Check if code block intersects a known coverage block
            boolean hitBlock = false;
            for (Map.Entry<Address, Integer> entry : ccBlockEntries.entrySet()) {

                // Get the start address of the coverage block
                Address ccBlockStart = entry.getKey();

                // Get the end address of the coverage block
                Address ccBlockEnd = ccBlockStart.add(entry.getValue());

                // Subtract 1 to prevent an overflow in the block search
                // (i.e. prevent execution false positives)
                ccBlockEnd = ccBlockEnd.subtract(1);

                // Check if block intersects with the coverage block
                if (block.intersects(ccBlockStart, ccBlockEnd)) {
                    hitBlock = true;
                    blocksHit.add(block);
                    break;
                }
            }

            // Loop through each block range
            for (AddressRange range : block.getAddressRanges()) {

                // Get the code units within the given range
                AddressSet set = new AddressSet(range);

                // Total instruction counter
                InstructionIterator iter = fnProgram.getListing().getInstructions(set, true);
                while (iter.hasNext()) {
                    totalInstructions += 1;
                    if (hitBlock) {
                        instructionsHit += 1;
                    }
                    iter.next();
                }
            }
        });

        // Indicate that model processing has finished
        processed = true;
    }
    
    /**
     * Gets the Ghidra function associated with this coverage function.
     * 
     * @return  Ghidra function
     */
    public Function getFunction() {
        return function;
    }
    
    /**
     * Gets the entry point of the function.
     * 
     * @return  Address of the function's entry point
     */
    public Address getEntryPoint() {
        return entryPoint;
    }
    
    /**
     * Gets the list of coverage blocks for the function.
     * 
     * @return  Hashmap of coverage blocks
     */
    public Map<Address, Integer> getCoverageBlocks() {
        return ccBlockEntries;
    }
    
    /**
     * Adds a coverage block to the list of coverage block entries.
     * 
     * @param address  Address of the coverage block
     * @param size     Size of the coverage block
     */
    public void addCoverageBlock(Address address, Integer size) {
        ccBlockEntries.put(address, size);
    }
    
    /**
     * Gets the total number of basic blocks in the function.
     * 
     * @return  Number of basic blocks
     */
    public long getTotalBlocks() {
        return totalBlocks;
    }
    
    /**
     * Gets the total number of instructions in the function.
     * 
     * @return  Number of instructions
     */
    public long getTotalInstructions() {
        return totalInstructions;
    }
    
    /**
     * Gets the list of code blocks that were hit inside the function.
     * 
     * @return  List of CodeBlock objects
     */
    public List<CodeBlock> getBlocksHit() {
        return blocksHit;
    }
    
    /**
     * Adds a block to the list of blocks hit.
     * 
     * @param block  CodeBlock to add to the hit list
     */
    public void addBlockHit(CodeBlock block) {
        blocksHit.add(block);
    }
    
    /**
     * Removes a block from the list of blocks hit.
     * 
     * @param block  CodeBlock to remove from the hit list
     */
    public void removeBlockHit(CodeBlock block) {
        blocksHit.remove(block);
    }
    
    /**
     * Gets the number of instructions that were hit inside the function.
     * 
     * @return  Number of executed instructions
     */
    public long getInstructionsHit() {
        return instructionsHit;
    }
    
    /**
     * Sets the number of instructions that were hit inside the function.
     * 
     * @param count  Number of executed instructions
     */
    public void setInstructionsHit(long count) {
        instructionsHit = count;
    }
    
    /**
     * Gets the size of the function in bytes
     * 
     * @return  Byte count of the function
     */
    public long getFunctionSize() {
        return functionSize;
    }
    
    /**
     * Checks whether the coverage function has been processed.
     * 
     * @return  True if the coverage function has been processed, false if not
     */
    public boolean isProcessed() {
        return processed;
    }
}
