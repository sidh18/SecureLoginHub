package com.example.loginapp.service;

import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@Service
public class SamlMetadataService {

    /**
     * Generate SP Metadata XML
     */
    public String generateSpMetadata(String entityId, String acsUrl) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.newDocument();

            // Root element
            Element metadata = doc.createElement("md:EntityDescriptor");
            metadata.setAttribute("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata");
            metadata.setAttribute("entityID", entityId);
            doc.appendChild(metadata);

            // SPSSODescriptor
            Element spDescriptor = doc.createElement("md:SPSSODescriptor");
            spDescriptor.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
            metadata.appendChild(spDescriptor);

            // NameIDFormat
            Element nameIdFormat = doc.createElement("md:NameIDFormat");
            nameIdFormat.setTextContent("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            spDescriptor.appendChild(nameIdFormat);

            // AssertionConsumerService
            Element acs = doc.createElement("md:AssertionConsumerService");
            acs.setAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            acs.setAttribute("Location", acsUrl);
            acs.setAttribute("index", "0");
            spDescriptor.appendChild(acs);

            // Convert to string
            return documentToString(doc);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Parse IDP Metadata and extract configuration
     */
    public Map<String, String> parseIdpMetadata(String metadataXml) {
        Map<String, String> config = new HashMap<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(metadataXml.getBytes()));

            // Extract Entity ID
            Element root = doc.getDocumentElement();
            String entityId = root.getAttribute("entityID");
            config.put("entityId", entityId);

            // Extract SSO URL
            NodeList ssoList = doc.getElementsByTagName("SingleSignOnService");
            if (ssoList.getLength() > 0) {
                Element ssoElement = (Element) ssoList.item(0);
                String ssoUrl = ssoElement.getAttribute("Location");
                config.put("ssoUrl", ssoUrl);
            }

            // Extract Certificate
            NodeList certList = doc.getElementsByTagName("X509Certificate");
            if (certList.getLength() > 0) {
                Element certElement = (Element) certList.item(0);
                String certificate = certElement.getTextContent().trim();
                config.put("certificate", certificate);
            }

            // Extract Logout URL
            NodeList logoutList = doc.getElementsByTagName("SingleLogoutService");
            if (logoutList.getLength() > 0) {
                Element logoutElement = (Element) logoutList.item(0);
                String logoutUrl = logoutElement.getAttribute("Location");
                config.put("logoutUrl", logoutUrl);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return config;
    }

    /**
     * Convert XML Document to String
     */
    private String documentToString(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.getBuffer().toString();
    }
}