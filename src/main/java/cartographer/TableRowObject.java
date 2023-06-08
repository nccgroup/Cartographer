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

import java.awt.Color;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Represents a row in the Code Coverage function table.
 */
public class TableRowObject {

    private Function function;
    private CoverageFunction ccFunc;
    private double coveragePercent;
    private Color bgColor;

    /**
     * Initializes a table row from a given coverage function.
     * 
     * @param ccFunc  Coverage function
     */
    TableRowObject(CoverageFunction ccFunc) {
        this.ccFunc = ccFunc;
        this.function = ccFunc.getFunction();

        // Check for division by zero
        if (ccFunc.getTotalInstructions() == 0) {
            this.coveragePercent = 0;
        }
        else {
            this.coveragePercent = ((double)ccFunc.getInstructionsHit() / ccFunc.getTotalInstructions());
            this.coveragePercent *= 100;
        }
    }

    /**
     * Sets the background color for the row based on the coverage amount.
     * <p>
     * Note: For any row with a non-zero coverage, the resulting row color will
     * be a value between the high and low colors based on the percentage of
     * the function that was executed.
     * </p>
     * 
     * @param highCoverage  Color to use for high coverage
     * @param lowCoverage   Color to use for low coverage
     * @param noCoverage    Color to use for no coverage
     */
    public void setBGColors(Color highCoverage, Color lowCoverage, Color noCoverage) {
        if (this.coveragePercent == 0.0f) {
            bgColor = noCoverage;
        }
        else {
            int rr = lowCoverage.getRed();
            int rg = lowCoverage.getGreen();
            int rb = lowCoverage.getBlue();
            int br = highCoverage.getRed();
            int bg = highCoverage.getGreen();
            int bb = highCoverage.getBlue();
            int nr = rr + (int)(this.coveragePercent * (br - rr) / 100);
            int ng = rg + (int)(this.coveragePercent * (bg - rg) / 100);
            int nb = rb + (int)(this.coveragePercent * (bb - rb) / 100);
            bgColor = new Color(nr, ng, nb);
        }
    }

    /**
     * Gets the function associated with this row.
     * 
     * @return  Ghidra function
     */
    public Function getFunction() {
        return function;
    }

    /**
     * Gets the name of the function.
     * 
     * @return  Function name
     */
    public String getFunctionName() {
        return function.getName();
    }

    /**
     * 
     * Gets the entry point (address) of the function.
     * 
     * @return  Address of the function
     */
    public Address getFunctionAddress() {
        return function.getEntryPoint();
    }

    /**
     * Gets the total blocks in the coverage function.
     * 
     * @return  Number of basic blocks
     */
    public long getTotalBlocks() {
        return ccFunc.getTotalBlocks();
    }

    /**
     * Gets the number of blocks hit in the coverage function.
     * 
     * @return  Number of blocks hit
     */
    public long getBlocksHit() {
        return ccFunc.getBlocksHit().size();
    }

    /**
     * Gets the total number of instructions in the function.
     * 
     * @return  Number of instructions
     */
    public long getTotalInstructions() {
        return ccFunc.getTotalInstructions();
    }

    /**
     * Gets the number of instructions hit in the coverage function.
     * 
     * @return  Number of executed instructions
     */
    public long getInstructionsHit() {
        return ccFunc.getInstructionsHit();
    }

    /**
     * Sets the number of instructions hit in the coverage function.
     * 
     * @param hitCount  Number of executed instructions
     */
    public void setInstructionsHit(long hitCount) {
        ccFunc.setInstructionsHit(hitCount);
    }

    /**
     * Gets the size of the function in bytes.
     * 
     * @return  Byte count of the function
     */
    public long getFunctionSize() {
        return ccFunc.getFunctionSize();
    }

    /**
     * Gets the execution percentage of the associated function.
     * 
     * @return  Percentage of function execution
     */
    public double getCoveragePercent() {
        return coveragePercent;
    }

    /**
     * Sets the execution percentage of the associated function.
     * 
     * @param percent  Percentage of function execution
     */
    public void setCoveragePercent(double percent) {
        coveragePercent = percent;
    }
    
    /**
     * Gets the background color of the row.
     * 
     * @return  Background color
     */
    public Color getBGColor() {
        return bgColor;
    }
}
