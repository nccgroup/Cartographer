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

import java.util.Map;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.CodeUnitIterator;

/**
 * Represents a tokenizer for parsing logical operations on code coverage data.
 */
public class ExpressionTokenizer {

    /**
     * Tokens for detecting each part of the logical expression.
     */
    private enum Token {
        AND,        //    &    Selects data present in both coverages
        OR,         //    |    Selects data present in either coverage
        XOR,        //    ^    Selects data that differs between coverages
        SUB,        //    -    Selects all data not present in next coverage
        LPAREN,     //    (    Start of an expression group
        RPAREN,     //    )    End of an expression group
        VAR,        //         Letter(s) representing the coverage file (ID)
        END         //         End of expression
    }

    /**
     * Tokenizer class to detect the type of token being processed.
     */
    public static class Tokenizer {
        final String input;
        int pos = 0;
        int coverageId;

        /**
         * Initializes the tokenizer with the given input.
         * 
         * @param input  String to feed into the tokenizer
         */
        public Tokenizer(String input) {
            this.input = input;
        }

        /**
         * Resets the tokenizer.
         */
        public void reset() {
            pos = 0;
            coverageId = 0;
        }

        /**
         * Gets the string processed up until the current position.
         * 
         * @return  input string up to current position
         */
        private String getProcessed() {
            return input.substring(0, pos);
        }

        /**
         * Gets the next token in the string.
         * 
         * @return  next token to process
         */
        private Token getNextToken() {
            coverageId = 0;

            // Ignore all whitespace up until the next token
            while (pos < input.length() && Character.isWhitespace(input.charAt(pos))) {
                ++pos;
            }

            // Return the END token if no more tokens exist
            if (pos >= input.length()) {
                return Token.END;
            }

            // Get the current position and prepare to move to the next token
            int start = pos++;

            // Check which token is being processed
            switch (input.charAt(start)) {
                case '(':
                    return Token.LPAREN;
                case ')':
                    return Token.RPAREN;
                case '&':
                    return Token.AND;
                case '|':
                    return Token.OR;
                case '^':
                    return Token.XOR;
                case '-':
                    return Token.SUB;
                default:
                    StringBuilder alphaId = new StringBuilder();
                    // Capture the entire alphabetical ID
                    while (start < input.length() && input.charAt(start) >= 'A' && input.charAt(start) <= 'Z') {
                        alphaId.append(input.charAt(start++));
                        pos++;
                    }
                    // Convert the alphabetical ID to a numeric ID
                    coverageId = Utils.alphaToId(alphaId.toString());
                    return Token.VAR;
            }
        }
    }

    /**
     * Expression evaluator that performs logical operations on the data.
     */
    public static class Evaluator {
        final Tokenizer tokenizer;
        final Map<Integer, CoverageFile> files;
        Token token;

        /**
         * Initializes the evaluator and kicks off the tokenizer.
         * 
         * @param tokenizer  Tokenizer to parse the expression string
         * @param files      All currently loaded coverage files in the plugin
         */
        public Evaluator(Tokenizer tokenizer, Map<Integer, CoverageFile> files) {
            this.tokenizer = tokenizer;
            this.files = files;
            nextToken();
        }

        /**
         * Gets the next token in the string.
         */
        private void nextToken() {
            token = tokenizer.getNextToken();
        }

        /**
         * Displays an error window with the given text.
         * <p>
         * Note: Also shows how much of the string was processed up until the
         * error occurred.
         * </p>
         * 
         * @param errorString  String describing the error
         */
        private void error(String errorString) {
            throw new AssertionError(errorString + "\n" +
                "Processed: " + tokenizer.getProcessed()
            );
        }

        /**
         * Ensures that the token being processed is the expected token.
         * 
         * @param expectedToken  Token expected to be encountered
         */
        private void expect(Token expectedToken) {
            if (token != expectedToken) {
                error(
                    "Expected:  " + expectedToken + "\n" +
                    "Found:     " + token
                );
            }
            nextToken();
        }

        /**
         * Calls the expression evaluator and ensures correct syntax.
         * 
         * @return  Result of the full evaluated expression
         */
        public CoverageFile evaluate() {
            CoverageFile exprVal = expr();
            expect(Token.END); 
            return exprVal;
        }

        /**
         * Evaluates a single expression based on the current token value.
         * 
         * @return  Result of the expression
         */
        private CoverageFile expr() {
            CoverageFile leftFile = operand();
            CoverageFile rightFile;
            CoverageFile resultsFile;
            
            // Check to see if the left file result should be returned
            if (token == Token.END) {
                return leftFile;
            }
            
            // Set the current token as the operator
            Token operator = token;
            
            // Check to see if non-operator was specified
            if (operator.compareTo(Token.SUB) > 0) {
                error("Expected expr, found " + token);
                return null;
            }
            
            // Check if no left-hand file was specified
            if (leftFile == null) {
                error("No left-hand variable specified");
                return null;
            }

            // Create a new coverage file to hold the results
            resultsFile = new CoverageFile(leftFile);

            // Move to the next token
            nextToken();

            // Get the right-hand coverage file
            rightFile = operand();

            // Check if no right-hand file was specified
            if (rightFile == null) {
                error("Expected right-hand variable");
                return null;
            }

            // Check which logical operation should be performed
            switch (operator) {

                // Remove any non-shared blocks from the resulting code coverage function
                case AND:
                    logicalAnd(leftFile, rightFile, resultsFile);
                    break;

                // Add any blocks on the right-hand side to the resulting code coverage function
                case OR:
                    logicalOr(leftFile, rightFile, resultsFile);
                    break;

                // Remove any shared blocks from the resulting code coverage function,
                // then add any exclusive blocks to the resulting code coverage function
                case XOR:
                    logicalXor(leftFile, rightFile, resultsFile);
                    break;

                // Only retain unique left-hand blocks within the resulting code coverage function
                case SUB:
                    logicalSub(leftFile, rightFile, resultsFile);
                    break;

                default:
                    break;
            }
            
            // Return the resulting coverage file data
            return resultsFile;
        }

        /**
         * Fetches a variable or the result of a grouped expression.
         * 
         * @return  Specified coverage or resulting coverage
         */
        private CoverageFile operand() {
            switch (token) {
                case VAR:
                    CoverageFile file = this.files.get(tokenizer.coverageId);
                    nextToken();
                    return file;
                case LPAREN:
                    nextToken();
                    CoverageFile exprVal = expr();
                    expect(Token.RPAREN);
                    return exprVal;
                default:
                    error("Expected operand, found " + token);
                    return null;
            }
        }
        
        /**
         * Performs a logical AND operation between two coverage files.
         * 
         * <p>
         * Note: The result of the AND operation is stored in the results file.
         * </p>
         * 
         * @param leftFile     Left-hand coverage file
         * @param rightFile    Right-hand coverage file
         * @param resultsFile  File storing the resulting coverage
         */
        private void logicalAnd(CoverageFile leftFile, CoverageFile rightFile, CoverageFile resultsFile) {
            leftFile.getCoverageFunctions().forEach((function, left) -> {
                CoverageFunction right = rightFile.getCoverageFunction(function);
                CoverageFunction result = resultsFile.getCoverageFunction(function);
                for (CodeBlock block : left.getBlocksHit()) {
                    if (!right.getBlocksHit().contains(block)) {
                        result.removeBlockHit(block);
                        result.setInstructionsHit(0);
                    }
                }
            });
        }

        /**
         * Performs a logical OR operation between two coverage files.
         * 
         * <p>
         * Note: The result of the OR operation is stored in the results file.
         * </p>
         * 
         * @param leftFile     Left-hand coverage file
         * @param rightFile    Right-hand coverage file
         * @param resultsFile  File storing the resulting coverage
         */
        private void logicalOr(CoverageFile leftFile, CoverageFile rightFile, CoverageFile resultsFile) {
            leftFile.getCoverageFunctions().forEach((function, left) -> {
                CoverageFunction right = rightFile.getCoverageFunction(function);
                CoverageFunction result = resultsFile.getCoverageFunction(function);
                for (CodeBlock block : right.getBlocksHit()) {
                    if (!result.getBlocksHit().contains(block)) {
                        result.addBlockHit(block);
                        result.setInstructionsHit(right.getInstructionsHit());
                    }
                }
            });
        }
        
        /**
         * Performs a logical XOR operation between two coverage files.
         * 
         * <p>
         * Note: The result of the XOR operation is stored in the results file.
         * </p>
         * 
         * @param leftFile     Left-hand coverage file
         * @param rightFile    Right-hand coverage file
         * @param resultsFile  File storing the resulting coverage
         */
        private void logicalXor(CoverageFile leftFile, CoverageFile rightFile, CoverageFile resultsFile) {
            leftFile.getCoverageFunctions().forEach((function, left) -> {
                CoverageFunction right = rightFile.getCoverageFunction(function);
                CoverageFunction result = resultsFile.getCoverageFunction(function);
                for (CodeBlock block : left.getBlocksHit()) {
                    if (right.getBlocksHit().contains(block)) {
                        result.removeBlockHit(block);
                        result.setInstructionsHit(0);
                    }
                }
                for (CodeBlock block : right.getBlocksHit()) {
                    if (!left.getBlocksHit().contains(block)) {
                        result.addBlockHit(block);
                        result.setInstructionsHit(right.getInstructionsHit());
                    }
                }
            });
        }
        
        /**
         * Subtracts coverage data found in the right-hand coverage file from
         * the coverage data found in the left-hand coverage file.
         * 
         * <p>
         * Note: The result of the SUB operation is stored in the results file.
         * </p>
         * 
         * @param leftFile     Left-hand coverage file
         * @param rightFile    Right-hand coverage file
         * @param resultsFile  File storing the resulting coverage
         */
        private void logicalSub(CoverageFile leftFile, CoverageFile rightFile, CoverageFile resultsFile) {
            leftFile.getCoverageFunctions().forEach((function, left) -> {
                CoverageFunction right = rightFile.getCoverageFunction(function);
                CoverageFunction result = resultsFile.getCoverageFunction(function);
                for (CodeBlock block : left.getBlocksHit()) {
                    if (right.getBlocksHit().contains(block)) {
                        result.removeBlockHit(block);
                        CodeUnitIterator iter1 = left.getFunction()
                                .getProgram()
                                .getListing()
                                .getCodeUnits(block, true);
                        while (iter1.hasNext()) {
                            result.setInstructionsHit(result.getInstructionsHit() - 1);
                            iter1.next();
                        }
                    }
                }
            });
        }
    }
}
