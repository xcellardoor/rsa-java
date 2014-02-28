package rsa;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;

/** Class holding input/output methods to text files and keys.
 *
 * @author S162320
 */

public class RSAFileInputOutput {
    
    Charset charset = Charset.forName("US-ASCII");
    RSAKeysAndValues RSAKeys = new RSAKeysAndValues();

    /** Method to read the ciphertext out of its file and store it in the rawCipherText field of RSAKeysAndValues
     *
     * @param readPath This parameter is of type Path and is the file path where the ciphertext is to be read from. This variable should be scraped
     * as an argument from the command line.
     */
    public void readCiphertextFromFile(Path readPath) {
        String line;
        String textFromFile = "";
        try (BufferedReader reader = Files.newBufferedReader(readPath, charset)) {
            while ((line = reader.readLine()) != null) {
                textFromFile = textFromFile + line;
            }
        } catch (IOException x) {
        }
        RSAKeysAndValues.rawCipherText = new BigInteger(textFromFile);
    }

    /**This method reads the text containing the phrase to be encrypted, and then assigns it to the static variable rawPlaintext.
     * This method takes a path to a secret text file as argument.
     *
     * @param readPath This parameter must be of type Path and this is where the method reads from for the plaintext.
     */
    public void readPlainTextFromFile(Path readPath) {
        String line;
        String textFromFile = "";
        try (BufferedReader reader = Files.newBufferedReader(readPath, charset)) {
            while ((line = reader.readLine()) != null) {
                textFromFile = textFromFile + line;
            }
        } catch (IOException x) {
        }
        RSAKeysAndValues.rawPlaintext = textFromFile;
    }

    /**Writes the encoded and RSA encrypted BigInteger to file for use later. Takes a path and BigInteger as arguments. The BigInteger is converted to a string
     * before being written to the file.
     *
     * @param writePath This is the path that the ciphertext is written to.
     * @param text The ciphertext that is to be written to the given path.
     */
    public void writeCiphertextToFile(Path writePath, BigInteger text) {
        try (BufferedWriter writer = Files.newBufferedWriter(writePath, charset)) {
            String stringified = text.toString();
            writer.write(stringified);
            writer.close();
        } catch (IOException x) {
        }

    }

    /**Write text to file, used for the decoded and deciphered text. Takes a path and String of text as arguments, writing the String to the file.
     *
     * @param writePath The path where the plaintext is to be written to.
     * @param text The text that is to be written to the Path location. Can you type what I say as I say it
     */
    public void writePlainTextToFile(Path writePath, String text) {
        try (BufferedWriter writer = Files.newBufferedWriter(writePath, charset)) {
            String stringified = text;
            writer.write(stringified);
            writer.close();
        } catch (IOException x) {
        }

    }
    
    /**This method reads the public key from file and writes the modulus and exponent within to static variables for later use.
     *
     * @param readPath The Path where the public key is to be read from
     */
    public void readPublicKeyFromFile(Path readPath) {
        String line;
        String textFromFile = "";
        try (BufferedReader reader = Files.newBufferedReader(readPath, charset)) {
            while ((line = reader.readLine()) != null) {
                textFromFile = textFromFile + line;
            }
        } catch (IOException x) {
        }
        String[] nAndEArray = textFromFile.split(":");
        RSAKeys.setN(new BigInteger(nAndEArray[0]));
        RSAKeys.setE(new BigInteger(nAndEArray[1]));
        
    }

    /**This method reads the public key from file and writes the modulus and exponent within to static variables for later use.
     *
     * @param readPath The path from which the private key is to be read from
     */
    public void readPrivateKeyFromFile(Path readPath) {
        String line;
        String textFromFile = "";
        try (BufferedReader reader = Files.newBufferedReader(readPath, charset)) {
            while ((line = reader.readLine()) != null) {
                textFromFile = textFromFile + line;
            }
        } catch (IOException x) {
        }
        String[] nAndEArray = textFromFile.split(":");
        RSAKeys.setN(new BigInteger(nAndEArray[0]));
        RSAKeys.setD(new BigInteger(nAndEArray[1]));
    }

    /**This function takes three arguments, a Path, Modulus, and Exponent, and writes the key to file! This method is key-agnostic.
     *
     * @param writePath The full path of where the key is to be written to.
     * @param n The key modulus
     * @param e The key exponent
     */
    public void writeKeyToFile(Path writePath, BigInteger n, BigInteger e) {
        String combinedNandE;
        combinedNandE = n.toString()+":"+e.toString();
        
        try (BufferedWriter writer = Files.newBufferedWriter(writePath, charset)) {
            writer.write(combinedNandE);
            writer.close();
        } catch (IOException x) {
        }

    }
    
}