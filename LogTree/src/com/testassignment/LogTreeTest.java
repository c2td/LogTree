package com.testassignment;

import org.slf4j.LoggerFactory;

/**
 * A class for running and testing the LogTree implementation
 */
public class LogTreeTest {

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(LogTree.class);

    public static void main(String[] args) {

        checkArgs(args);
        LogTree logTree = new LogTree();

        // build and sign a tree based on the input file
        logTree.constructTree(args);

        // validate a specified log entry
        if (args.length > 1) {
            if (logTree.isValidLogEntry(args[1])) {
                LOGGER.info("Log entry is valid");
            } else {
                LOGGER.info("Log entry or logfile is not valid");
            }

        } else {
            LOGGER.info("Nothing to validate. Please provide a log entry");
        }
    }

    /**
     * Helper method for checking if program arguments are valid
     */
    private static void checkArgs(String[] args) {

        if (args.length < 1) {
            LOGGER.info(
                    "Please provide at least a filename, usage: java program filename [log_entry] [trusted_roothash]");
            System.exit(0);
        }
    }

}
