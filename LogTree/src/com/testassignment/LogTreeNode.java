package com.testassignment;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.LoggerFactory;

/**
 * An object representation of one node in the tree
 */
public class LogTreeNode {

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(LogTreeNode.class);

    private LogTreeNode leftChild;
    private LogTreeNode rightChild;
    private LogTreeNode parent;
    private byte[] value;

    public LogTreeNode(LogTreeNode leftChild, LogTreeNode rightChild, byte[] value) {
        this.leftChild = leftChild;
        this.rightChild = rightChild;
        this.value = value;
    }

    /**
     * Returns true if the node is a leaf node
     */
    public boolean isLeaf() {
        return leftChild == null && rightChild == null;
    }

    /**
     * Returns true if the node is a root node
     */
    public boolean isRoot() {
        return parent == null;
    }

    /**
     * Returns the node value as byte array
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * Returns true if the node is a left child
     */
    public boolean isLeftChild() {
        return this.equals(parent.getLeftChild());
    }

    /**
     * Returns the left child of the node. Returns null for leaf node
     */
    public LogTreeNode getLeftChild() {
        return leftChild;
    }

    /**
     * Returns the right child of the node. Returns null for leaf node
     */
    public LogTreeNode getRightChild() {
        return rightChild;
    }

    /**
     * Returns the parent node of the node. Returns null for root node
     */
    public LogTreeNode getParent() {
        return parent;
    }

    /**
     * Sets the parent node value for the node
     */
    public void setParent(LogTreeNode parent) {
        this.parent = parent;
    }

    /**
     * Prints out node's children, parent and value data
     */
    public void info() {
        LOGGER.info("value: " + DatatypeConverter.printHexBinary(value) + " " + this + ", L: " + leftChild + ", R: "
                + rightChild + ", P: " + parent);
    }

}
