import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // Configuration fields
    private boolean enableInterception = true;
    private String serverHost = "localhost";
    private int serverPort = 3333;
    private boolean filterInScope = true;

    // UI components
    private JPanel mainPanel;
    private JTextField hostField;
    private JTextField portField;
    private JCheckBox inScopeCheckBox;
    private JCheckBox enableInterceptionCheckBox;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Set the name of the extension
        callbacks.setExtensionName("JXScout");

        // Register the HTTP listener
        callbacks.registerHttpListener(this);

        // Initialize helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Load persisted settings
        loadConfig();

        // Initialize the UI
        initUI();

        // Register the custom tab
        callbacks.addSuiteTab(this);

        // Register the context menu factory
        callbacks.registerContextMenuFactory(this);
    }

    private void initUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Add padding to the main panel
        JPanel paddedPanel = new JPanel(new BorderLayout());
        paddedPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Add 10px padding on all sides
        paddedPanel.add(mainPanel, BorderLayout.CENTER);

        // Title and description
        JLabel titleLabel = new JLabel("JXScout Settings");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(titleLabel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Add spacing

        JLabel descriptionLabel = new JLabel("Configure ingestion from Burp to JXScout");
        descriptionLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        descriptionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(descriptionLabel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 20))); // Add spacing

        // Configuration fields
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        configPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        configPanel.setMaximumSize(new Dimension(400, 150)); // Set fixed width

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Enable Interception checkbox
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Enable Interception:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        enableInterceptionCheckBox = new JCheckBox();
        enableInterceptionCheckBox.setSelected(enableInterception);
        configPanel.add(enableInterceptionCheckBox, gbc);

        // Host field
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Server Host:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        hostField = new JTextField(serverHost, 20);
        configPanel.add(hostField, gbc);

        // Port field
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Server Port:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        portField = new JTextField(String.valueOf(serverPort), 10);
        configPanel.add(portField, gbc);

        // In-scope checkbox
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Filter In-Scope:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        inScopeCheckBox = new JCheckBox();
        inScopeCheckBox.setSelected(filterInScope);
        configPanel.add(inScopeCheckBox, gbc);

        mainPanel.add(configPanel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 20))); // Add spacing

        // Save button
        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveButton.setMaximumSize(new Dimension(100, 30)); // Set fixed width for button
        saveButton.addActionListener(e -> saveConfig());
        mainPanel.add(saveButton);

        // Set the padded panel as the main panel
        mainPanel = paddedPanel;
    }

    private void saveConfig() {
        try {
            serverHost = hostField.getText();
            serverPort = Integer.parseInt(portField.getText());
            filterInScope = inScopeCheckBox.isSelected();
            enableInterception = enableInterceptionCheckBox.isSelected();
            // Save settings using Burp's persistence mechanism
            callbacks.saveExtensionSetting("serverHost", serverHost);
            callbacks.saveExtensionSetting("serverPort", String.valueOf(serverPort));
            callbacks.saveExtensionSetting("filterInScope", String.valueOf(filterInScope));
            callbacks.saveExtensionSetting("enableInterception", String.valueOf(enableInterception));

            callbacks.printOutput("Configuration saved: Host=" + serverHost + ", Port=" + serverPort + ", FilterInScope=" + filterInScope + ", EnableInterception=" + enableInterception);

            // Show success message
            JOptionPane.showMessageDialog(mainPanel, "Settings saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException e) {
            callbacks.printError("Invalid port number");

            // Show error message
            JOptionPane.showMessageDialog(mainPanel, "Invalid port number. Please enter a valid number.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadConfig() {
        // Load settings using Burp's persistence mechanism
        String savedHost = callbacks.loadExtensionSetting("serverHost");
        String savedPort = callbacks.loadExtensionSetting("serverPort");
        String savedFilterInScope = callbacks.loadExtensionSetting("filterInScope");
        String savedEnableInterception = callbacks.loadExtensionSetting("enableInterception");
        // Apply loaded settings or use defaults if not set
        serverHost = (savedHost != null) ? savedHost : "localhost";
        serverPort = (savedPort != null) ? Integer.parseInt(savedPort) : 3333;
        filterInScope = (savedFilterInScope != null) ? Boolean.parseBoolean(savedFilterInScope) : true;
        enableInterception = (savedEnableInterception != null) ? Boolean.parseBoolean(savedEnableInterception) : true;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        if (!messageIsRequest) {
            byte[] request = message.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            URL requestUrl = requestInfo.getUrl();
            
            if (filterInScope && !callbacks.isInScope(requestUrl)) {
                return;
            }
            
            if (!enableInterception) {
                return;
            }

            try {
                byte[] responseData = message.getResponse();
                String rawRequest = new String(request);
                String rawResponse = new String(responseData);

                JSONObject jsonPayload = new JSONObject();
                String urlWithoutPort = requestUrl.getProtocol() + "://" + requestUrl.getHost() + requestUrl.getFile();
                jsonPayload.put("requestUrl", urlWithoutPort);
                jsonPayload.put("request", rawRequest);
                jsonPayload.put("response", rawResponse);

                sendToServer(message);

                callbacks.printOutput("Request/Response sent to JXScout server successfully");
            } catch (Exception e) {
                callbacks.printError("Error sending to JXScout server: " + e.getMessage());
            }
        }
    }

    private void sendToServer(IHttpRequestResponse message) {
        try {
            byte[] request = message.getRequest();
            byte[] response = message.getResponse();
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            URL requestUrl = requestInfo.getUrl();
            
            JSONObject jsonPayload = new JSONObject();
            String urlWithoutPort = requestUrl.getProtocol() + "://" + requestUrl.getHost() + requestUrl.getFile();
            jsonPayload.put("requestUrl", urlWithoutPort);
            jsonPayload.put("request", new String(request));
            jsonPayload.put("response", new String(response));
            
            // Send to JXScout server
            URL url = new URL("http://" + serverHost + ":" + serverPort + "/caido-ingest");
            IHttpService httpService = helpers.buildHttpService(
                url.getHost(),
                url.getPort() == -1 ? 80 : url.getPort(),
                false
            );
            
            // Build the request with headers and body
            List<String> headers = new ArrayList<>();
            headers.add("POST /caido-ingest HTTP/1.1");
            headers.add("Host: " + url.getHost() + (url.getPort() != -1 ? ":" + url.getPort() : ""));
            headers.add("Content-Type: application/json");
            headers.add("Content-Length: " + jsonPayload.toString().getBytes("utf-8").length);
            headers.add("");
            
            byte[] jxscoutRequest = helpers.buildHttpMessage(headers, jsonPayload.toString().getBytes("utf-8"));
            
            // Send request through Burp
            IHttpRequestResponse jxscoutResponse = callbacks.makeHttpRequest(httpService, jxscoutRequest);
            
            if (jxscoutResponse != null && jxscoutResponse.getResponse() != null) {
                callbacks.printOutput("Data sent to JXScout server successfully");
            } else {
                callbacks.printError("Failed to send data to JXScout server: No response received");
            }
        } catch (Exception e) {
            callbacks.printError("Failed to send data to server: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "JXScout";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        JMenuItem sendToServerMenuItem = new JMenuItem("Send to jxscout");
        
        sendToServerMenuItem.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            // Move HTTP request to a separate thread
            new Thread(() -> {
                for (IHttpRequestResponse message : messages) {
                    try {
                        sendToServer(message);
                        callbacks.printOutput("Request/Response sent to JXScout server successfully");
                    } catch (Exception ex) {
                        callbacks.printError("Error sending to JXScout server: " + ex.getMessage());
                    }
                }
            }).start();
        });
        
        menuItems.add(sendToServerMenuItem);

        // Add new menu item for sending JavaScript files
        JMenuItem sendJavaScriptFilesMenuItem = new JMenuItem("Send JavaScript files");
        
        sendJavaScriptFilesMenuItem.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            // Move HTTP requests to a separate thread
            new Thread(() -> {
                for (IHttpRequestResponse message : messages) {
                    try {
                        byte[] response = message.getResponse();
                        String responseStr = new String(response);
                        IRequestInfo requestInfo = helpers.analyzeRequest(message);
                        URL baseUrl = requestInfo.getUrl();
                        
                        // Extract JavaScript files from response
                        List<String> jsFiles = extractJavaScriptFiles(responseStr, baseUrl);
                        
                        // Log all extracted URLs
                        callbacks.printOutput("Found " + jsFiles.size() + " JavaScript files:");
                        for (String jsFile : jsFiles) {
                            callbacks.printOutput("  - " + jsFile);
                        }
                        
                        // Process each JavaScript file
                        for (String jsFile : jsFiles) {
                            try {
                                URL jsUrl = new URL(jsFile);
                                
                                // Create HTTP request using Burp's API
                                byte[] request = helpers.buildHttpRequest(jsUrl);
                                IHttpService httpService = helpers.buildHttpService(
                                    jsUrl.getHost(),
                                    jsUrl.getPort() == -1 ? (jsUrl.getProtocol().equals("https") ? 443 : 80) : jsUrl.getPort(),
                                    jsUrl.getProtocol().equals("https")
                                );
                                
                                IHttpRequestResponse jsResponse = callbacks.makeHttpRequest(
                                    httpService,
                                    request
                                );
                                
                                if (jsResponse != null && jsResponse.getResponse() != null) {
                                    // Send directly to JXScout
                                    sendToServer(jsResponse);
                                    callbacks.printOutput("JavaScript file sent to JXScout server: " + jsFile);
                                } else {
                                    callbacks.printError("Failed to fetch JavaScript file: " + jsFile);
                                }
                            } catch (Exception ex) {
                                callbacks.printError("Error fetching JavaScript file " + jsFile + ": " + ex.getMessage());
                            }
                        }
                    } catch (Exception ex) {
                        callbacks.printError("Error processing JavaScript files: " + ex.getMessage());
                    }
                }
            }).start();
        });
        
        menuItems.add(sendJavaScriptFilesMenuItem);
        return menuItems;
    }

    private List<String> extractJavaScriptFiles(String response, URL baseUrl) {
        List<String> jsFiles = new ArrayList<>();
        String pattern = "<script[^>]*src=[\"']([^\"']+)[\"'][^>]*>";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(response);
        
        while (m.find()) {
            String jsPath = m.group(1);
            try {
                // Handle different URL formats
                String absoluteUrl;
                if (jsPath.startsWith("http://") || jsPath.startsWith("https://")) {
                    // Already absolute URL
                    absoluteUrl = jsPath;
                } else if (jsPath.startsWith("//")) {
                    // Protocol-relative URL
                    absoluteUrl = baseUrl.getProtocol() + ":" + jsPath;
                } else if (jsPath.startsWith("/")) {
                    // Root-relative URL
                    absoluteUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                jsPath;
                } else {
                    // Relative URL - need to handle the base path correctly
                    String basePath = baseUrl.getPath();
                    // Remove the filename from the base path to get the directory
                    String baseDir = basePath.substring(0, basePath.lastIndexOf('/') + 1);
                    // Combine the base directory with the relative path
                    String combinedPath = baseDir + jsPath;
                    // Normalize the path (remove any ".." or "." segments)
                    try {
                        java.net.URI normalizedUri = new java.net.URI(null, null, combinedPath, null).normalize();
                        absoluteUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                    (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                    normalizedUri.getPath();
                    } catch (Exception e) {
                        // If normalization fails, use the combined path as is
                        absoluteUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() + 
                                    (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + 
                                    combinedPath;
                    }
                }
                
                // Normalize URL (remove double slashes except after protocol)
                absoluteUrl = absoluteUrl.replaceAll("(?<!:)//+", "/");
                
                jsFiles.add(absoluteUrl);
                callbacks.printOutput("Found JavaScript file: " + absoluteUrl);
            } catch (Exception e) {
                callbacks.printError("Error processing JavaScript URL: " + jsPath + " - " + e.getMessage());
            }
        }
        
        return jsFiles;
    }
}