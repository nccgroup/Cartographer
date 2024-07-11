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
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Toolkit;
import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;

/**
 * Class for convenience utilities.
 */
public class Utils {
    
    /**
     * Ensures that this class can't be instantiated.
     */
    private Utils() {
        throw new IllegalStateException("Cannot construct utility class.");
    }

    /**
     * Displays an error message dialog to the user.
     * 
     * @param code     Error code
     * @param message  Details about the error
     */
    public static void showError(String code, String message) {

        // Label for status code
        JLabel status = new JLabel("ERROR: " + code);

        // Text area for status message
        JTextArea details = new JTextArea(message);
        details.setEditable(false);

        // Visually differentiate the message to make it stand out
        details.setBackground(new Color(0xCC, 0xCC, 0xCC));

        // Add both components to a new JPanel
        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(status);
        panel.add(Box.createVerticalStrut(20));
        panel.add(details);

        // Auto-resize the panel if too big
        autoResizePanel(panel);

        // Show the new panel
        JOptionPane.showMessageDialog(
            null,
            panel,
            "Error",
            JOptionPane.ERROR_MESSAGE
        );
    }

    /**
     * Displays an informational message dialog to the user.
     * 
     * @param message  Message to display
     */
    public static void showInfo(String message) {

        // Label for status code
        JLabel details = new JLabel(message);

        // Add both components to a new JPanel
        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(details);

        // Auto-resize the panel if too big
        autoResizePanel(panel);

        // Show the new panel
        JOptionPane.showMessageDialog(
            null,
            panel,
            message,
            JOptionPane.INFORMATION_MESSAGE
        );
    }

    /**
     * Resizes the panel automatically based on the window contents.
     * 
     * @param panel  Panel to resize
     */
    private static void autoResizePanel(JPanel panel) {

        // Get maximum dimensions
        Dimension maxDimensions = Toolkit.getDefaultToolkit().getScreenSize();
        double maxWidth = maxDimensions.getWidth();
        double maxHeight = maxDimensions.getHeight();

        // Make sure dimensions don't overflow past screen bounds
        double panelWidth = panel.getPreferredSize().getWidth();
        double panelHeight = panel.getPreferredSize().getHeight();
        if (panelWidth > maxWidth) {
            panelWidth = maxWidth / 2;
        }
        if (panelHeight > maxHeight) {
            panelHeight = maxHeight / 2;
        }

        // Set new size of the panel
        Dimension newSize = new Dimension();
        newSize.setSize(panelWidth, panelHeight);
        panel.setPreferredSize(newSize);
    }
    
    /**
     * Creates an alphabetical ID based on a numeric ID.
     * 
     * @param id  Numeric ID
     * 
     * @return    Alphabetical string ID
     */
    public static String idToAlpha(int id) {

        // Initial blank string
        String output = "";

        // Recursively call self to add characters to the string
        if ((id / 26) > 0) {
            output += idToAlpha((id / 26) - 1);
        }

        // Get the char representation of the ID
        output += (char)(0x41 + (id % 26));
        
        // Return the final string
        return output;
    }
    
    /**
     * Creates a numeric ID based on an alphabetical ID.
     * 
     * @param alphaId  Alphabetical string ID
     * 
     * @return         Numeric ID
     */
    public static int alphaToId(String alphaId) {

        // Initial output value
        int output = 0;
        
        // Truncate length to process multi-character IDs
        int processLength = alphaId.length() - 1;
        
        // Read each character of the string
        for (int i = 0; i < processLength; i++) {
            
            // Get the integer representation of the character
            // (Add one to account for initial overflow)
            int charVal = (alphaId.charAt(i) - 'A') + 1;
            
            // Multiply the value using its current place in the string
            output += charVal * Math.pow(26, (processLength - i));
        }
        
        // Add the value of the last character to the output
        output += alphaId.charAt(alphaId.length() - 1) - 'A';
        
        // Return the final string
        return output;
    }
}
