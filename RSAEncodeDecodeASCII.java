package rsa;

import java.math.BigInteger;

/**Class with methods for encoding and decoding strings to and from ASCII.
 *
 * @author S162320
 */
public class RSAEncodeDecodeASCII {

    /**
     * This method encodes ASCII-compatible text to it's ASCII representation.
     * Takes a single ASCII char as it's argument, and the returned data is an
     * Int of that character in ASCII.
     *
     * @param x parameter of type character to convert to a numerical representation
     * @return the numerical ASCII representation of the character passed into the method.
     */
    public Integer encodeLetterToASCII(char x) {
        int numericRepresentation = (int) x;
        return numericRepresentation;
    }

    /**
     * This method converts one ASCII numerical back to a letter - one at a
     * time. Takes an int as a parameter an returns the ASCII character as a
     * char.
     *
     * @param x Integer which is to be converted to its ASCII letter representation.
     * @return ASCII Character representation of the numerical value passed into the method.
     */
    public char decodeASCIIToLetter(int x) {
        char characterRepresentation = (char) x;
        return characterRepresentation;
    }

    /**
     * This method encodes the string passed to it as ASCII, with leading 0
     * padding on a letter value if under 100, and 111 padding at each end to
     * delimit the text, allowing for encoded text to start with an ASCII
     * numerical of value 0 (e.g 079). The encodeLetterToASCII method is used on
    *a per-letter basis to convert each letter of the string one at a time
    *Once the process completes the ASCIIPlaintext static value is
    *set in RSAKeysAndValues.
     *
     * @param x input string which is to be converted to ASCII.
     */
    public void encodeStringToASCII(String x) {
        String passedString = x;
        String result = "111";//Ensure that the first 111 padding is in place.
        for (int i = 0; i < passedString.length(); i++) {
            if (encodeLetterToASCII(passedString.charAt(i)) <= 99) {
                result = result.concat("0");
            }
            result = result.concat(encodeLetterToASCII(passedString.charAt(i)).toString());
        }
        result = result.concat("111");
        RSAKeysAndValues.ASCIIPlaintext = new BigInteger(result);
    }

    /**
     * This method takes a String of ASCII values (padded with zeros to be three
     * digits long) and converts them back to a String of letters. The
     * decodeASCIIToLetter function is called for each letter in the encoded
     * text, and the result is assigned to RSAKeysAndValues.normalisedText.
     *
     * @param x - string of type BigInteger which is to be decoded back to ASCII Characters
     */
    public void decodeASCIIToString(BigInteger x) {
        String passedString = x.toString();
        String result = "";
        String grabbedChar;
        for (int i = 0; i < passedString.length(); i = i + 3) {
            try {
                grabbedChar = passedString.substring(i, i + 3);
                result = result.concat(String.valueOf(decodeASCIIToLetter(Integer.parseInt(grabbedChar))));

            } catch (StringIndexOutOfBoundsException e) {
                System.out.println("\n!\n!\n!\n!!!!Decoding error, got an exception when trying to decode "
                        + "-are you using the right public key?!!!!\n!\n!\n!\n!");
            }
        }
        result = result.substring(1, result.length() - 1);
        RSAKeysAndValues.normalisedText = result;
    }
}
