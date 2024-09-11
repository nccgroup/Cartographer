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

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Represents a loaded coverage file with processed code coverage data.
 */
public class CoverageFile {

    /**
     * Status codes encountered when processing data.
     */
    public enum STATUS {
        OK("File loaded."),
        HEADER_ERROR("Unknown file header."),
        DRCOV_MODULE_VERSION_ERROR("Unknown DrCov Module version."),
        DRCOV_MODULE_TABLE_ERROR("DrCov Module error."),
        DRCOV_BBTABLE_ERROR("DrCov BB Table error."),
        DRCOV_MODULE_ERROR("DrCov Module error."),
        EZCOV_OPTION_ERROR("EZCov Option error."),
        BLOCK_ERROR("Block error.");

        private final String text;

        STATUS(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    private String type;
    private int version;
    private Map<String, DrCovModule> modules = new HashMap<>();
    private List<BasicBlock> blocks = new ArrayList<>();
    private STATUS statusCode;
    private String statusMessage;
    private String filename;
    private int id;
    private String alphaId;
    private CartographerModel model;

    // List of code coverage functions
    private Map<Function, CoverageFunction> ccFunctionMap = new HashMap<>();

    /**
     * Initializes a code coverage file object from an absolute file path.
     * 
     * @param filename      Absolute path of the code coverage file to analyze
     * 
     * @throws IOException  If an I/O exception occurred
     */
    public CoverageFile(String filename) throws IOException {

        // Filename without the pathname
        this.filename = filename.substring(filename.lastIndexOf('/') + 1);

        // Attempt to open the file
        try (RandomAccessFile reader = new RandomAccessFile(filename, "r")) {

            // Read the first line of the file
            String headerLine = reader.readLine();

            // Check if this is a DRCOV file
            if (headerLine.toLowerCase().startsWith("drcov")) {

                type = "drcov";

                // Parse the file
                parseDrCovFile(reader);
                statusCode = STATUS.OK;
            }

            // Check if this is an EZCOV file
            else if (headerLine.toLowerCase().startsWith("ezcov")) {

                type = "ezcov";

                // Get the version
                Matcher match = Pattern.compile("^EZCOV VERSION: (.*)").matcher(headerLine);
                if (match.find()) {
                    version = Integer.parseInt(match.group(1));
                }
                else {
                    statusCode = STATUS.HEADER_ERROR;
                    statusMessage = "Unknown EZCOV version. Found [" + headerLine + "]";
                }

                // Parse the file
                EzCovModule module = parseEzCovFile(reader);
                statusCode = STATUS.OK;

                // Copy module blocks to file blocks
                blocks = module.getBasicBlocks();
            }

            // Otherwise throw an error
            else {
                statusCode = STATUS.HEADER_ERROR;
                statusMessage = "Unknown coverage header: [" + headerLine + "]";
            }
        }

        // Whoops!
        catch (Exception e) {
            throw new AssertionError(e);
        }
    }
    
    /**
     * Copy constructor for a code coverage file.
     * 
     * @param file  Existing CoverageFile object to copy
     */
    public CoverageFile(CoverageFile file) {
        
        // Clone each function
        file.ccFunctionMap.forEach(
            (function, ccFunc) -> this.ccFunctionMap.put(function, new CoverageFunction(ccFunc))
        );
    }

    /**
     * Parses a DRCOV file.
     * 
     * @param reader        RandomAccessFile reader for the coverage file
     * 
     * @throws IOException  If an I/O exception occurred
     */
    private void parseDrCovFile(RandomAccessFile reader) throws IOException {

        // Placeholder line
        String line = null;
        List<DrCovModule> drcovModules = new ArrayList<>();

        // Skip DRCOV FLAVOR header
        reader.readLine();

        // Module version
        line = reader.readLine();
        
        // Default to no modules
        int numModules = 0;
        
        // Get the module count and version, if applicable
        Matcher match = Pattern.compile("^Module Table: (?:version (\\d+), count )?(\\d+)$").matcher(line);
        
        // Update strings if any matches were found
        if (match.find()) {
            // Default to version 1 if module table version doesn't exist
            version = Integer.parseInt((match.group(1) != null) ? match.group(1) : "1");
            numModules = Integer.parseInt(match.group(2));
        }
        
        // Skip column names if this wasn't a version 1 DRCOV module set
        if (version > 1) {
            reader.readLine();
        }

        // Parse each module
        for (int i = 0; i < numModules; i++) {

            // Read each module
            line = reader.readLine();
            String[] moduleData = line.split(",");
            
            // Read the DRCOV module data and add it to the list of modules
            DrCovModule module = parseDrCovModule(moduleData);
            drcovModules.add(module);
        }

        // Read the BB Table line
        line = reader.readLine();

        // Get the number of basic blocks
        match = Pattern.compile("^BB Table: (\\d+) bbs").matcher(line);
        int bbCount = 0;
        if (match.find()) {
            bbCount = Integer.parseInt(match.group(1));
        }

        // Get the next 6 bytes of the file
        boolean isBinary = false;
        long curPtr = reader.getFilePointer();
        byte[] bytes = new byte[6];
        reader.read(bytes);
        reader.seek(curPtr);

        // Check if this is a binary file
        if (!Arrays.equals(bytes, "module".getBytes())) {
            isBinary = true;
        }

        // Otherwise move to the next line (first text entry)
        else {
            reader.readLine();
        }

        // Loop through each entry
        for (int i = 0; i < bbCount; i++) {

            // Read binary block
            if (isBinary) {
                int offset = readInt(reader);
                short size = readShort(reader);
                int moduleId = readShort(reader) & 0xFFFF;

                // Make sure the module ID is valid
                if(moduleId < numModules){
                    // Add the block to the module
                    drcovModules.get(moduleId).addBlock(offset, size, moduleId);
                }
            }

            // Read a text block
            else {
                line = reader.readLine();
                match = Pattern.compile("module\\[\\s*(\\d+)\\]: 0x([0-9a-fA-F]+?),\\s*(\\d+)").matcher(line);
                if (match.find()) {
                    int moduleId = Integer.parseInt(match.group(1)) & 0xFFFF;
                    int offset = Integer.parseUnsignedInt(match.group(2), 16);
                    short size = Short.parseShort(match.group(3));
                    
                    // Make sure the module ID is valid
                    if(moduleId < numModules){
                        // Add the block to the module
                        drcovModules.get(moduleId).addBlock(offset, size, moduleId);
                    }
                }
            }
        }
        
        // Populate the module list
        populateModules(drcovModules);
    }

    /**
     * Parses a DRCOV module.
     * 
     * @param moduleData    List of module string data
     * 
     * @return              DRCOV module data
     */
    private DrCovModule parseDrCovModule(String[] moduleData) {
        
        // Module ID is always at position 0
        int moduleId = Integer.parseInt(moduleData[0].trim());
        
        // File path always comes last
        String name = moduleData[moduleData.length-1].trim();
        
        // Default parent ID and base position for versions 1 and 2
        int parentId = 0;
        int basePos = 1;
        
        // Process versions 3 and above
        if (version > 2) {
            
            // Versions 3, 4, and 5 all have the parent ID at position 1
            parentId = Integer.parseInt(moduleData[1].trim());
            
            // Version 3 has the base address at position 2
            if (version == 3) {
                basePos = 2;
            }
            
            // Versions 4 and 5 have the base address at position 5
            else {
                basePos = 5;
            }
        }
        
        // Get the base address based on its position
        long base = Long.parseUnsignedLong(moduleData[basePos].trim().replace("0x", ""), 16);
        
        // Create and return the DrCovModule from the parsed module entry
        DrCovModule module = new DrCovModule(moduleId, parentId, base, name);
        return module;
    }
    
    /**
     * Populates the map of usable modules with those read from the DRCOV file.
     * 
     * @param modList  List of DrCovModule objects
     */
    private void populateModules(List<DrCovModule> modList) {
        
        // Loop through each module
        for (DrCovModule module : modList) {

            // Make sure module list entry exists
            if (!modules.containsKey(module.name)) {
                DrCovModule newMod = new DrCovModule(module.moduleId, module.parentId, module.base, module.name);
                modules.put(module.name, newMod);
            }

            // Get the specified module
            DrCovModule newMod = modules.get(module.name);

            // Add each block to the new module
            for (BasicBlock block : module.getBasicBlocks()) {
                // Add the base address to the offset if this was a v5 module
                if (version == 5) {
                    block.offset += module.base;
                }
                newMod.addBlock(block.offset, block.size, block.moduleId);
            }

            // Add the new module to the module list
            modules.put(newMod.name, newMod);
        }
    }

    /**
     * Parses an EZCOV file.
     * 
     * @param reader        RandomAccessFile reader for the coverage file
     * 
     * @throws IOException  If an I/O exception occurred
     */
    private EzCovModule parseEzCovFile(RandomAccessFile reader) throws IOException {

        // Create a single EZCov module
        EzCovModule module = new EzCovModule();

        // Read the next line
        String line = reader.readLine();

        // Continue reading until no comments remain
        while (line != null) {

            // Skip any lines that start with a comment
            if (line.startsWith("#") || line.isBlank()) {
                line = reader.readLine();
                continue;
            }

            // Parse the thing
            Matcher match = Pattern.compile("^\\s*(0x[0-9a-fA-F]+?)\\s*,\\s*(\\d+)\\s*,\\s*\\[ (.*?) \\]").matcher(line);

            // Make sure a match was found
            if (match.find()) {

                // Get the matched data
                long offset = Long.decode(match.group(1));
                short size = Short.parseShort(match.group(2));
                String addressSpace = match.group(3);

                // Create a block from the data
                module.addBlock(offset, size, addressSpace);
            }

            // Read the next line
            line = reader.readLine();
        }

        // Return the module
        return module;
    }

    /**
     * Reads a 32-bit integer value from the specified file stream.
     * 
     * @param r             RandomAccessFile to read from
     * 
     * @return              32-bit integer
     * 
     * @throws IOException  If an I/O exception occurred
     */
    private int readInt(RandomAccessFile r) throws IOException {
        return r.read() | (r.read() << 8) | (r.read() << 16) | (r.read() << 24);
    }

    /**
     * Reads a 16-bit short value from the specified file stream.
     * 
     * @param r             RandomAccessFile to read from
     * 
     * @return              16-bit short
     * 
     * @throws IOException  If an I/O exception occurred
     */
    private short readShort(RandomAccessFile r) throws IOException {
        return (short)(r.read() | (r.read() << 8));
    }

    /**
     * Represents a code coverage module containing individual basic blocks.
     */
    public class CodeCoverageModule {
        private List<BasicBlock> basicBlocks = new ArrayList<>();
        
        public List<BasicBlock> getBasicBlocks() {
            return basicBlocks;
        }
    }

    /**
     * Represents a DRCOV module.
     */
    public class DrCovModule extends CodeCoverageModule {

        private int moduleId;
        private int parentId;
        private long base;
        private String name;

        /**
         * Constructor for a DRCOV module.
         * 
         * @param moduleId  Module ID 
         * @param parentId  Parent module ID
         * @param base      Base memory address
         * @param name      Name of the file
         */
        public DrCovModule(int moduleId, int parentId, long base, String name) {
            this.moduleId = moduleId;
            this.parentId = parentId;
            this.base = base;
            this.name = name;
        }

        /**
         * Adds a block to the DRCOV module.
         * 
         * @param offset  Offset of the block from the module's base address
         * @param size    Size of the block in bytes
         * @param module  Module ID
         */
        private void addBlock(long offset, short size, int module) {
            BasicBlock basicBlock = new BasicBlock(offset, size, module);
            this.getBasicBlocks().add(basicBlock);
        }
    }

    /**
     * Represents an EZCOV module.
     */
    public class EzCovModule extends CodeCoverageModule {

        /**
         * Constructor for an EZCOV module.
         */
        public EzCovModule() {
            // Nothing set upon initialization
        }

        /**
         * Adds a block to the EZCOV module.
         * 
         * @param offset        Memory offset of the block
         * @param size          Size of the block in bytes
         * @param addressSpace  Address space of the block
         */
        private void addBlock(long offset, short size, String addressSpace) {
            BasicBlock basicBlock = new BasicBlock(offset, size, addressSpace);
            this.getBasicBlocks().add(basicBlock);
        }
    }

    /**
     * Represents a basic block.
     */
    public class BasicBlock {
        private long offset;
        private short size;
        private int moduleId;
        private AddressSpace addressSpace;

        /**
         * Constructor for a basic block using a module ID.
         * 
         * @param offset    Memory offset of the block
         * @param size      Size of the block in bytes
         * @param moduleId  Module ID
         */
        public BasicBlock(long offset, short size, int moduleId) {
            this.offset = offset;
            this.size = size;
            this.moduleId = moduleId;
        }

        /**
         * Constructor for a basic block using an address space.
         * 
         * @param offset        Memory offset of the block
         * @param size          Size of the block in bytes
         * @param addressSpace  Address space of the block
         */
        public BasicBlock(long offset, short size, String addressSpace) {
            this.offset = offset;
            this.size = size;
            this.addressSpace = CartographerPlugin.getAddressSpace(addressSpace);
        }

        /**
         * Constructor for a generic basic block.
         * 
         * @param offset  Memory offset of the block
         * @param size    Size of the block in bytes
         */
        public BasicBlock(long offset, short size) {
            this.offset = offset;
            this.size = size;
        }
    }

    /**
     * Gets the string representation of the file in the selector dropdown.
     */
    public String toString() {
        return this.alphaId + " (" + this.filename + ")";
    }
    
    /**
     * Populates the block entries for the coverage function.
     * 
     * @param program  Current program being analyzed
     */
    public void populateBlocks(Program program) {
        
        // Loop through each basic block
        for (BasicBlock block : this.blocks) {

            // Check for no matches
            if (block.addressSpace == null) {
                block.addressSpace = program.getListing()
                        .getDefaultRootModule()
                        .getMinAddress()
                        .getAddressSpace();
            }

            // Get the address within the address space
            Address address = block.addressSpace.getAddressInThisSpaceOnly(block.offset);

            // Check if address is relative to the address space offset
            Address spaceOffset = block.addressSpace.getMinAddress();
            if (address.compareTo(spaceOffset) < 0) {
                address = address.add(spaceOffset.getOffset());
            }

            // Add base offset to address if needed
            Address baseOffset = program.getImageBase();
            if (address.compareTo(baseOffset) < 0) {
                address = address.add(baseOffset.getOffset());
            }

            // Get the function that the address belongs to
            Function checkFunction = program.getFunctionManager().getFunctionContaining(address);

            // Make sure function being checked exists
            if (checkFunction != null) {

                // Add the current execution address to the list of blocks hit
                CoverageFunction ccFunc = this.ccFunctionMap.get(checkFunction);
                ccFunc.addCoverageBlock(address, Integer.valueOf(block.size));
            }
        }
    }
    
    /**
     * Gets the detected type of the coverage file.
     * 
     * @return  Type of coverage file
     */
    public String getType() {
        return type;
    }
    
    /**
     * Gets the detected version of the coverage file.
     * 
     * @return  Version of coverage file
     */
    public int getVersion() {
        return version;
    }
    
    /**
     * Gets the list of loaded modules.
     * 
     * @return  Hashmap of modules
     */
    public Map<String, DrCovModule> getModules() {
        return modules;
    }
    
    /**
     * Gets a specified module by name.
     * 
     * @param moduleName  Name of the module
     * 
     * @return            Module with the associated name
     */
    public DrCovModule getModule(String moduleName) {
        return modules.get(moduleName);
    }
    
    /**
     * Gets the list of loaded basic blocks.
     * 
     * @return  List of basic blocks
     */
    public List<BasicBlock> getBlocks() {
        return blocks;
    }
    
    /**
     * Sets the list of blocks to the specified list.
     * 
     * @param blocks  List of basic blocks
     */
    public void setBlocks(List<BasicBlock> blocks) {
        this.blocks = blocks;
    }
    
    /**
     * Gets the status code.
     * 
     * @return  Status code
     */
    public STATUS getStatusCode() {
        return statusCode;
    }
    
    /**
     * Gets the status message.
     * 
     * @return  Status message
     */
    public String getStatusMessage() {
        return statusMessage;
    }
    
    /**
     * Gets the filename of the coverage file.
     * 
     * @return  Name of the coverage file
     */
    public String getFilename() {
        return filename;
    }
    
    /**
     * Gets the unique ID of the coverage file.
     * 
     * @return  ID of the coverage file
     */
    public int getId() {
        return id;
    }
    
    /**
     * Sets the ID of the coverage file to the specified value.
     * 
     * @param id  Integer to use for the file's ID
     */
    public void setId(int id) {
        this.id = id;
    }
    
    /**
     * Gets the unique mnemonic ID of the coverage file.
     * 
     * @return  Mnemonic ID of the coverage file
     */
    public String getAlphaId() {
        return alphaId;
    }
    
    /**
     * Sets the mnemonic ID of the coverage file to the specified value.
     * 
     * @param id  String to use for the file's mnemonic ID
     */
    public void setAlphaId(String id) {
        this.alphaId = id;
    }
    
    /**
     * Gets the model used by the coverage file.
     * 
     * @return  Model used by the coverage file
     */
    public CartographerModel getModel() {
        return model;
    }
    
    /**
     * Sets the model for the coverage file.
     * 
     * @param model  Model to use for the file
     */
    public void setModel(CartographerModel model) {
        this.model = model;
    }
    
    /**
     * Gets a list of the coverage functions associated with the coverage file.
     * 
     * @return  Hashmap of coverage functions
     */
    public Map<Function, CoverageFunction> getCoverageFunctions() {
        return ccFunctionMap;
    }
    
    /**
     * Gets a specific coverage function identified by its Ghidra function.
     * 
     * @param fn  Ghidra function
     * 
     * @return    Coverage function
     */
    public CoverageFunction getCoverageFunction(Function fn) {
        return ccFunctionMap.get(fn);
    }
    
    /**
     * Adds a coverage function to the list of coverage functions.
     * 
     * @param fn      Ghidra function
     * @param ccFunc  Coverage function
     */
    public void addCoverageFunction(Function fn, CoverageFunction ccFunc) {
        ccFunctionMap.put(fn, ccFunc);
    }
    
    /**
     * Clears the coverage function list.
     */
    public void clearCoverageFunctions() {
        ccFunctionMap.clear();
    }
}
