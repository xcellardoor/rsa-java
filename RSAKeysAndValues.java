package rsa;

import java.math.BigInteger;


/** Class which generates keys and acts a central holding class for RSA values.
 *
 * @author S162320
 */

public class RSAKeysAndValues {
    private static BigInteger p;
    private static BigInteger q;
    private static BigInteger n;
    public static BigInteger totient;
    private static BigInteger e;
    private static BigInteger d;
    public static BigInteger gcd;
    public static BigInteger M;
    public static BigInteger C;
    public static BigInteger decryptedCipherText;
    public static BigInteger ASCIIPlaintext;
    public static BigInteger encryptedCipherText;
    public static BigInteger rawCipherText;
    public static String normalisedText;
    public static String rawPlaintext;
    private boolean isNotPrimeFlagP;
    private boolean isNotPrimeFlagQ;
    
    RSAMathematics RSAMaths = new RSAMathematics();

    /**Returns static BigInteger value E
     *
     * @return value e
     */
    public BigInteger getE() {
        return e;
    }

    /** Sets static BigInteger value e
     *
     * @param e
     */
    public void setE(BigInteger e) {
        RSAKeysAndValues.e = e;
    }

    /**getD() - returns static BigInteger d
     *
     * @return value d
     */
    public BigInteger getD() {
        return d;
    }

    /** set method for static BigInteger d
     *
     * @param d
     */
    public void setD(BigInteger d) {
        RSAKeysAndValues.d = d;
    }

    /** get method for static BigInteger n
     *
     * @return
     */
    public BigInteger getN() {
        return n;
    }

    /** set method for static BigInteger n
     *
     * @param n
     */
    public void setN(BigInteger n) {
        RSAKeysAndValues.n = n;
    }

    /**generateKeyPair - generates a Public and Private keypair, calling on multiple other functions to achieve this including a prime creation method, a
     * Fermat primality test and sets static values accordingly.
     *
     * @param bitLength The bitlength of the keys which are going to be generated, such as 1024, 2048, 4096
     */
    public void generateKeyPair(int bitLength) {
         do{
            RSAKeysAndValues.p = RSAMaths.createPrimeofBitLength(bitLength);
            RSAKeysAndValues.q = RSAMaths.createPrimeofBitLength(bitLength);
            
            //Print the primes to screen so we know how far in the process we are.
            System.out.println("\nP: "+p);
            System.out.println("\nQ: "+q);
    
            //isNotPrimeFlagP = RSAMaths.checkProbablePrime(p,bitLength);
            //isNotPrimeFlagQ = RSAMaths.checkProbablePrime(q,bitLength);
            isNotPrimeFlagP = RSAMaths.fermatPrimalityTest(p, 500);
            isNotPrimeFlagQ = RSAMaths.fermatPrimalityTest(q, 500);
        } while (!(isNotPrimeFlagP && isNotPrimeFlagQ)); //<-If both are primes, then it's True && True - so the while loop keeps running! We need to NOT flag this,
                                                            //so we get a false and the while expression breaks and we leave the loop;
        System.out.println("\nIs P prime? - "+isNotPrimeFlagP);
        System.out.println("IS Q prime? - "+isNotPrimeFlagQ);

        RSAKeysAndValues.n = p.multiply(q);

        //Assign static variables in holding class.
        RSAKeysAndValues.totient = RSAMaths.calculateTotient(p,q);
        RSAKeysAndValues.e = RSAMaths.generateEValue(RSAKeysAndValues.totient);
        RSAKeysAndValues.d = RSAMaths.generateDValue(RSAKeysAndValues.e, RSAKeysAndValues.totient);
    }
}
