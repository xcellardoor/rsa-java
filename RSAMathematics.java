package rsa;

import java.math.BigInteger;
import java.util.Random;

/**
 * Collection of mathematical methods relating to RSA.
 *
 * @author S162320
 * 
 */
public class RSAMathematics {

    BigInteger r;
    BigInteger a;
    private BigInteger cipherText;
    private BigInteger decryptedCipherText;
    private BigInteger calculatedTotient;
    Random rnd = new Random();


    /** Custom Modular Inverse using Extended Euclidian Table Method - takes two BigIntegers as arguments and calculates their greatest common denominator.
     *
     * @param a
     * @param b
     * @return Greatest Common Denominator
     */
    //Pseudocode converted from Wikipedia to use BigInteger and work-around lack of parrallel assignment of values in Java - see notes
    public BigInteger modularInverseExtEuclid(BigInteger a, BigInteger b) {
        //Assign
        BigInteger s = BigInteger.ZERO;
        BigInteger old_s = BigInteger.ONE;
        BigInteger t = BigInteger.ONE;
        BigInteger old_t = BigInteger.ZERO;
        BigInteger r = b;
        BigInteger old_r = a;
        BigInteger prov;

        while (!r.equals(BigInteger.ZERO)) { //Keep running while r equals 0 is NOT(!) true
            BigInteger quotient = old_r.divide(r);

            prov = r;
            r = old_r.subtract(quotient.multiply(prov));
            old_r = prov;

            //This code is not needed... we aren't hunting for these values of the table and since they don't impact any of the other calculations, we can comment
            //them out.
//            prov = s;
//            s = old_s.subtract(quotient.multiply(prov));
//            old_s = prov;
//
//            prov = t;
//            t = old_t.subtract(quotient.multiply(prov));
//            old_t = prov;
        }
        return old_r;
    }

    /**This method calls themodInverse function and generates a value for the public key exponent.
     *
     * @param e - 
     * @param totient
     * @return
     */
    public BigInteger generateDValue(BigInteger e, BigInteger totient) {
        BigInteger result;
        result = e.modInverse(totient);
        return result;
    }

    /**
     * This method returns a prime with the bitLength specified as an argument
     * when invoked.
     *
     * @param bitLength - An int value which causes the method to generate a
     * prime of a bitLength marching this parameter.
     * @return Prime number of specified bitlength
     */
    public BigInteger createPrimeofBitLength(int bitLength) {
        BigInteger primeToReturn = BigInteger.probablePrime(bitLength, rnd);
        
        return primeToReturn;
    }

    /**
     * This method checks whether n is a probable prime.
     *
     * @param n - prime number to check
     * @return - return whether that number is prime or not.
     */
    public boolean checkProbablePrime(BigInteger n) {
        boolean isItPrime;
        isItPrime = fermatPrimalityTest(n, 50);
        if (isItPrime==true){
            return true;
        }
        else return false;
               
    }
    
    /**
     * This custom method takes in a BigInteger which is a prime number for testing,
     * and an integer value which in essence decides the accuracy of the
     * primality test.
     *
     * @param valueToTest
     * @param howManyTimes
     * @return
     */
    public boolean fermatPrimalityTest(BigInteger valueToTest, int howManyTimes) {
        BigInteger a = null;
        for (int repeatCount = 0; repeatCount < howManyTimes; repeatCount++) {
            //pick a randomly from range 1, n-1
            do {
                a = new BigInteger(valueToTest.bitLength(), rnd);
            } while (a.compareTo(BigInteger.ONE) > 0 && a.compareTo(valueToTest) < 0);
            // old a = a.modPow(valueToTest.subtract(BigInteger.ONE), valueToTest);
            a = modularExponentiation(a, valueToTest.subtract(BigInteger.ONE), valueToTest);
            //a = a.modPow(valueToTest.subtract(BigInteger.ONE), valueToTest);
            if (!a.equals(BigInteger.ONE)) {
                return false; //composite
            }
        }
        return true; //prime
    }

    /**
     * Euclidian Algorithm used for computing the greatest common denominator
     * Takes two parameters, and returns the greatest common denominator
     *
     * @param a - BigInteger for the algorithm
     * @param b - BigInteger for the algorithm
     * @return - Return a if when b has been reduced to 0.
     */
    public BigInteger euclidianAlgorithm(BigInteger a, BigInteger b) {
        if (b.compareTo(BigInteger.ZERO) == 0) {        // <-if the value of b, when compared to 0, is zero, then they are matched.
            return a;
        } else {
            return euclidianAlgorithm(b, a.mod(b));
        }
        
    }

    /**
     * Custom method creates a prime which is smaller and coprime to x. Useful
     * when creating the exponent of the public key.
     *
     * @param x - Prime number which we are to create a relative prime to.
     * @return - A prime number that is smaller than the number passed in.
     */
    public BigInteger createRelativePrime(BigInteger x) {
        BigInteger z; //initialise
        do {
            z = BigInteger.probablePrime(rnd.nextInt(x.bitLength()-1), rnd); // make value z a probableprime of bitLength less than that of X
        } while (!euclidianAlgorithm(x, z).equals(BigInteger.ONE) && !z.equals(BigInteger.valueOf(2)) && !fermatPrimalityTest(z,50)); //<- NOT the output, as only false breaks the while loop,
        // and check that z is not 2, as two is not a usable prime
        return z;
    }

    /**
     * encryptMessage(BigInteger Message, BigInteger modulus, BigInteger
     * exponent) This method takes in the three aforementioned parameters and
     * then calls the custom modularExponentiation method to calculate the
     * cipher output.
     *
     * @param M - BigInteger Message
     * @param n - BigInteger Modulus part of public key
     * @param e - BigUnteger Exponent part of public key
     */
    public void encryptMessage(BigInteger M, BigInteger n, BigInteger e) {
        cipherText = modularExponentiation(M, e, n);  //M.modPow(e,n);
        RSAKeysAndValues.encryptedCipherText = cipherText;
    }

    /**
     * decryptMessage(BigInteger cipher, BigInteger modulus, BigInteger private
     * exponent) This method takes in the three values, and then calls the
     * custom modularExponentiation method to calculate the numerical ASCII
     * encoded text.
     *
     * @param C - Encrypted BigInteger
     * @param n - Modulus part of Private Key
     * @param d - exponent part of private key
     */
    public void decryptMessage(BigInteger C, BigInteger n, BigInteger d) {
        decryptedCipherText = modularExponentiation(C, d, n); //C.modPow(d,n);
        RSAKeysAndValues.decryptedCipherText = decryptedCipherText;
    }

    /**
     * This method calculates the totient value of two BigInteger's which are
     * passed to it, p and q.
     *
     * @param p - first value to use when calculating totient
     * @param q - second value to use when calculating totient
     * @return Totient value
     */
    public BigInteger calculateTotient(BigInteger p, BigInteger q) {
        BigInteger valueP = p;
        BigInteger valueQ = q;
        calculatedTotient = valueP.subtract(BigInteger.ONE).multiply(valueQ.subtract(BigInteger.ONE));
        return calculatedTotient;
    }

    /**
     * Generates the Public key exponent, e, needs a bit length and the totient
     * passed to it in that order, of type BigInteger.
     *
     * @param totient - used for calculating the exponent value.
     * @return public exponent
     */
    public BigInteger generateEValue(BigInteger totient) {
        BigInteger eValue; //create eValue
        eValue = createRelativePrime(totient);
        return eValue;
    }

    /**
     * A custom version of modularExponentiation to replace the built-in
     * BigInteger function, pass in BigInt base, exponent, and modulus. This
     * method is used for encryption and decryption of numerical data using the
     * keys.
     *
     * @param M 
     * @param e
     * @param n
     * @return Result of modular exponentiation
     */
    public BigInteger modularExponentiation(BigInteger M, BigInteger e, BigInteger n) {
        BigInteger base = M;
        BigInteger exponent = e;
        BigInteger modulus = n;
        BigInteger result = BigInteger.ONE;
        BigInteger current_bit;

        while (exponent.compareTo(BigInteger.ZERO) == 1) {
            current_bit = exponent.mod(BigInteger.valueOf(2));
            if (current_bit.equals(BigInteger.ONE)) {
                result = ((result.multiply(base).mod(modulus)));
            }
            exponent = exponent.divide(BigInteger.valueOf(2));
            base = (base.multiply(base)).mod(modulus);
        }
        return result;
    }
}
