package rsa;

import java.nio.file.FileSystems;
import java.nio.file.Path;

/**
 * RSA Tool for Java Assignment 3.
 *
 * @author S162320
 * @version 1.0
 */
public class RSA {

    
    private static void displayHelp(){
        System.out.println("Syntax:");
        System.out.println("    generatekeys #bitlength #pathtosavepublickey #pathtosaveprivatekey");
        System.out.println("    encrypt #publickeypath #secretmessagepath #ciphertextoutputpath");
        System.out.println("    decrypt #privatekeypath #ciphertextreadpath #decryptedtextoutputpath");
    }
    
    /**
     * Program Main - This main reads in arguments specified on the command line
     * during the program's launch, and these control the flow of the whole
     * program.
     *
     * @param args This is an array populated by the arguments on the command
     * line
     */
    public static void main(String[] args) {

        //Create instances of classes we shall use.
        RSAMathematics RSAMaths = new RSAMathematics();
        RSAFileInputOutput RSAFileIO = new RSAFileInputOutput();
        RSAEncodeDecodeASCII CodeASCII = new RSAEncodeDecodeASCII();
        RSAKeysAndValues RSAKeys = new RSAKeysAndValues();

        //Check that arguments have been passed, if they haven't, quit and explain why.
        if (args.length == 0) {
            System.out.println("You have not provided any arguments for the program to use!");
            displayHelp();
            System.exit(1);//Quit
        }
        //Otherwise do nothing, other traps will get the execution flow

        //If "generatekeys" is the first argument, run this set of instructions
        //Ensure that for generating keys, there is a second value which is used for keysize
        if ("generatekeys".equals(args[0]) && (args.length == 4) && (Integer.parseInt(args[1]) > Integer.valueOf(20))) {

            //Call the generateKeyPair function and pass in the bitlength which was specified as an argument.
            RSAKeys.generateKeyPair(Integer.parseInt(args[1]));
            System.out.println("\nPublic Modulus: " + RSAKeys.getN());
            System.out.println("\nPublic Exponent: " + RSAKeys.getE());

            System.out.println("\nPrivate Modulus: " + RSAKeys.getN());
            System.out.println("\nPrivate Exponent: " + RSAKeys.getD());

            Path publicKeyPath = FileSystems.getDefault().getPath(args[2]);
            Path privateKeyPath = FileSystems.getDefault().getPath(args[3]);

            RSAFileIO.writeKeyToFile(publicKeyPath, RSAKeys.getN(), RSAKeys.getE());
            RSAFileIO.writeKeyToFile(privateKeyPath, RSAKeys.getN(), RSAKeys.getD());
        } //If the first argument is "encrypt", run this set of instructions
        //Path Syntax - public key, text, cipher text
        else if ("encrypt".equals(args[0]) && (args.length == 4)) {
            Path publicKeyPath = FileSystems.getDefault().getPath(args[1]);
            Path secretMessagePath = FileSystems.getDefault().getPath(args[2]);
            Path cipherTextPath = FileSystems.getDefault().getPath(args[3]);
            
            RSAFileIO.readPublicKeyFromFile(publicKeyPath);

            RSAFileIO.readPlainTextFromFile(secretMessagePath);
            System.out.println("\nThe original data is: " + RSAKeysAndValues.rawPlaintext + "\n");

            CodeASCII.encodeStringToASCII(RSAKeysAndValues.rawPlaintext);
            System.out.println("\nEncoded to ASCII: " + RSAKeysAndValues.ASCIIPlaintext);

            RSAMaths.encryptMessage(RSAKeysAndValues.ASCIIPlaintext, RSAKeys.getN(), RSAKeys.getE());
            System.out.println("\nThe Encrypted data is " + RSAKeysAndValues.encryptedCipherText);

            RSAFileIO.writeCiphertextToFile(cipherTextPath, RSAKeysAndValues.encryptedCipherText);
        } // If the word "decrypt" is the first, run this set list of instructions.
        // Path Syntax - private key, encryptedText, decryptedCipherText text
        else if ("decrypt".equals(args[0]) && args.length == 4) {
            Path privateKeyPath = FileSystems.getDefault().getPath(args[1]);
            Path encryptedTextPath = FileSystems.getDefault().getPath(args[2]);
            Path decryptedTextPath = FileSystems.getDefault().getPath(args[3]);

            RSAFileIO.readCiphertextFromFile(encryptedTextPath);
            System.out.println("\n" + "Ciphertext from file " + encryptedTextPath.toString() + ": ");
            System.out.println(RSAKeysAndValues.rawCipherText + "\n");
            RSAFileIO.readPrivateKeyFromFile(privateKeyPath);

            //System.out.println("N "+RSAKeys.getN());
            //System.out.println("D "+RSAKeys.getD());
            //Perform the decryption on the BigInteger from the cipherfile, with the modulus and private exponent.
            RSAMaths.decryptMessage(RSAKeysAndValues.rawCipherText, RSAKeys.getN(), RSAKeys.getD());

            //Decode the concatenated ASCII back to a string
            CodeASCII.decodeASCIIToString(RSAKeysAndValues.decryptedCipherText);

            //Write out the decrypted text to file, and print it to screen, as required by the Assignment.
            RSAFileIO.writePlainTextToFile(decryptedTextPath, RSAKeysAndValues.normalisedText);
            System.out.println("Decrypted Text is: \n" + RSAKeysAndValues.normalisedText);
        } //If the first argument on the CLI is "help", print these syntax tips out.
        else if ("help".equals(args[0]) && args.length == 1) {
            displayHelp();
        } //Anything else is probably a wrong argument and we should terminate
        else {
            System.out.println("Wrong arguments - use the argument 'help' for syntax examples");
            displayHelp();
            System.exit(1);
        }
    }
}
