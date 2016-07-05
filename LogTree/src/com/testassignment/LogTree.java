package com.testassignment;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.LoggerFactory;

import com.guardtime.ksi.unisignature.KSISignature;

/**
 * The class constructs a binary tree with hash values (a Merkle tree) for a
 * specified text input (logfile) Enables to verify if a logfile entry excerpt
 * is part of the tree
 */
public class LogTree {

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(LogTree.class);
    private final static String ALGORITHM = "SHA-256";
    private final static Charset UTF8_CHARSET = StandardCharsets.UTF_8;
    private List<LogTreeNode> leafNodes;
    private LogTreeNode rootNode;
    private byte[] trustedRoot;

    /**
     * Constructs a binary hash tree from the input log and signs the root hash
     */
    public void constructTree(String[] args) {

        // generate leaf nodes from log entries
        leafNodes = new LinkedList<LogTreeNode>(getLeafNodes(args[0]));

        // start building a tree upwards from leaves
        createLogTreeNodes(leafNodes);

        // sign the root hash
        signRootHash(rootNode.getValue());

        // use the trusted root if provided externally, otherwise the one
        // calculated here is used
        if (args.length == 3) {
            trustedRoot = args[2].getBytes(UTF8_CHARSET);
        } else {
            trustedRoot = rootNode.getValue();
        }
    }

    /**
     * Recursively builds a tree level from the given nodes
     */
    private void createLogTreeNodes(List<LogTreeNode> nodes) {

        if (nodes.size() == 0) {
            return;
        } else if (nodes.size() == 1) { // if root node was reached, store it
            rootNode = nodes.get(0);
            LOGGER.info("Reached the root node: " + DatatypeConverter.printHexBinary(rootNode.getValue()) + "\n");
            return;
        } else if (nodes.size() % 2 == 1) {
            // in case of odd number of leaves the last one is duplicated
            nodes.add(nodes.get(nodes.size() - 1));
        }

        LOGGER.info("Starting with new level of nodes: " + nodes.size());

        // reset the array for adding new parent nodes
        List<LogTreeNode> newNodes = new LinkedList<LogTreeNode>();

        // output some log data about the nodes
        for (LogTreeNode node : nodes) {
            node.info();
        }

        for (int i = 0; i < nodes.size(); i += 2) {

            LogTreeNode leftChild = nodes.get(i);
            LogTreeNode rightChild = nodes.get(i + 1);

            // append two child node hashes and create the parent node
            byte[] preHash = getSiblingsHash(leftChild, rightChild);
            LogTreeNode parent = new LogTreeNode(leftChild, rightChild, createNodeHash(preHash));
            newNodes.add(parent);
            leftChild.setParent(parent);
            rightChild.setParent(parent);
        }

        // continue the process with the newly calculated nodes
        createLogTreeNodes(newNodes);
    }

    /**
     * Parses the input log file entry rows and returns their node objects list
     */
    private List<LogTreeNode> getLeafNodes(String fileName) {

        List<LogTreeNode> leafNodes = new LinkedList<LogTreeNode>();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(fileName)))) {

            for (String line; (line = br.readLine()) != null;) {
                byte[] nodeHash = createNodeHash(line.getBytes(UTF8_CHARSET));

                // create and store the log tree leave objects
                leafNodes.add(new LogTreeNode(null, null, nodeHash));
            }

        } catch (FileNotFoundException e) {
            LOGGER.info("File does not exist in the given location.");
            System.exit(0);
        } catch (IOException e) {
            LOGGER.info("A problem occurred accessing the file.");
            System.exit(0);
        }

        return leafNodes;
    }

    /**
     * Creates and returns hash code byte list from input byte array
     */
    private byte[] createNodeHash(byte[] data) {

        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);

            md.update(data);
            byte[] hashBytes = md.digest();
            return hashBytes;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            LOGGER.info("Such algorithm does not exist");
            return null;
        }
    }

    /**
     * Signs the root hash bytes
     */
    private KSISignature signRootHash(byte[] hashBytes) {

        KSISignature signature = null;

        /*
         * 
         * // needs real URLs and authentication data..
         * 
         * String signingUrl = ""; String extendingUrl = ""; String
         * publicationsFileUrl = ""; KSIServiceCredentials credentials = new
         * KSIServiceCredentials("user", "password");
         * 
         * HttpClientSettings httpSettings = new HttpClientSettings(signingUrl,
         * extendingUrl, publicationsFileUrl, credentials); SimpleHttpClient
         * simpleHttpClient = new SimpleHttpClient(httpSettings);
         * 
         * try { KSI ksi = new KSIBuilder()
         * .setKsiProtocolSignerClient(simpleHttpClient)
         * .setKsiProtocolExtenderClient(simpleHttpClient)
         * .setKsiProtocolPublicationsFileClient(simpleHttpClient)
         * .setPublicationsFileTrustedCertSelector(new
         * X509CertificateSubjectRdnSelector("E=test@test.com")) .build();
         * 
         * signature = ksi.sign(hashBytes);
         * 
         * } catch (KSIException e) { e.printStackTrace(); }
         */

        return signature;
    }

    /**
     * Returns true if the trusted root node value matches the computed one
     */
    public boolean isValidLogEntry(String inputText) {

        LOGGER.info("Tree was built, starting the validation part...\n");

        // obtain the list of hashes from the leaf node to the root node
        LinkedList<byte[]> hashPath = new LinkedList<>(getHashPath(inputText.getBytes(UTF8_CHARSET)));

        // return true if the computed root hash matches the trusted root hash
        // value
        return Arrays.equals(hashPath.getLast(), trustedRoot);
    }

    /**
     * Returns a path of hashes from leaf to root
     */
    private List<byte[]> getHashPath(byte[] inputText) {

        LinkedList<byte[]> hashes = new LinkedList<>();
        LogTreeNode currentNode = null;

        // start filling the hash values list by adding the leaf value first
        hashes.add(createNodeHash(inputText));

        LOGGER.info("Calculated leaf hash: " + DatatypeConverter.printHexBinary(hashes.get(0)));

        // search for the hash in the existing leaf nodes
        boolean leafFound = false;
        for (LogTreeNode node : leafNodes) {

            if (Arrays.equals(node.getValue(), hashes.get(0))) {
                LOGGER.info("Matching leaf hash: " + DatatypeConverter.printHexBinary(node.getValue()) + "\n");
                hashes.add(createNodeHash(
                        getSiblingsHash(node.getParent().getLeftChild(), node.getParent().getRightChild())));
                currentNode = node.getParent();
                leafFound = true;
            }
        }

        if (!leafFound) {
            LOGGER.info("Such log entry does not exist in the file");
        }

        // continue until root node is reached
        while (leafFound && !currentNode.isRoot()) {
            currentNode = currentNode.getParent();
            hashes.add(createNodeHash(getSiblingsHash(currentNode.getLeftChild(), currentNode.getRightChild())));
        }

        LOGGER.info("Hash chain to the root:\n");

        for (byte[] bytes : hashes) {
            LOGGER.info(DatatypeConverter.printHexBinary(bytes));
        }
        return hashes;
    }

    /**
     * Returns a concatenation of sibling hashes as a byte array
     */
    private byte[] getSiblingsHash(LogTreeNode leftChild, LogTreeNode rightChild) {

        byte[] preHash = new byte[leftChild.getValue().length + rightChild.getValue().length];
        System.arraycopy(leftChild.getValue(), 0, preHash, 0, leftChild.getValue().length);
        System.arraycopy(rightChild.getValue(), 0, preHash, leftChild.getValue().length, rightChild.getValue().length);

        return preHash;
    }
}