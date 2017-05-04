/*********************************************************************
  RSA.java

  -- A simplified RSA encryption implementation.
***********************************************************************/

public class RSA {
    // Approximate bounds for randomly generated primes.
        /* we are only dealing with very small primes
           (not more than '7.5' bits = 2^7 + 2^6) since we want to guarantee
           that any intermediate values to fit into
           32-bit signed int, i.e. no larger than pow(2,31)-1. */
    public static final int PRIME_LOW_BOUND = 61; // 'big' enough
    public static final int PRIME_HIGH_BOUND = 192; /* not too big to cause
                                                         potential overflow */

    // Approximate bound for encryption/decryption keys
    public static final int KEY_LOW_BOUND = 31; // so key not 'too' small

    // The max allowed value of the message text (integer) to be encrypted.
    public static final int MAX_INPUT_MESSAGE =
            PRIME_LOW_BOUND * PRIME_LOW_BOUND - 1;

    /* Test whether a number is prime
     Parameters:
       n - number to be tested
     Returns:
       true|false - whether the number is a prime
     */
    public static boolean testPrime(int n) {
        boolean result = true;

        if(n == 2 || n == 3) result = true;
        else if(n == 1 || n % 2 == 0) result = false;
        else {
        	// if n has divisor x then either x or n/x is <= sqrt(n)
        	// so we only look for divisor up to sqrt(n)
        	int sqrt = (int) Math.sqrt(n) + 1;	
        	for (int i = 3; i < sqrt; i += 2) {
				if (n % i == 0) {
					result = false;
					break;
				}
			}
        }
        return result;
    }

    /* Randomly generate a prime number roughly in the range of
     [PRIME_LOW_BOUND, RPIME_HIGH_BOUND).
     */
    public static int genPrime() {
        int n = (int)(Math.random() * (PRIME_HIGH_BOUND - PRIME_LOW_BOUND))
                + PRIME_LOW_BOUND; // generate a random number int the range
        if(n % 2 == 0)  // if n is even, it can't be prime
            n--;
        while(!testPrime(n)) // repeat until a prime is found
            n -= 2;
        return n;
    }
    
    /* Find the greatest common divisor (gcd) of two positive numbers,
     n1 and n2.
     */
    public static int gcd(int n1, int n2) {
        int divisor = 1;

        if (n1 < n2) { // make sure n1 is max(n1, n2) and n2 is the min
        	int temp = n1;
        	n1 = n2;
        	n2 = temp;
        }       
        if (n2 < 0 || n1 < 1) 	// assuming args are non-negative and one of them is non-zero
        	throw new IllegalArgumentException();  
        
      // iterative version of gcd(n1,n2) = gcd(n2, n1%n2)
    	int r;
    	while (n2 != 0) {	
    		r = n1 % n2;
    		n1 = n2;
    		n2 = r;
    	}
    	divisor = n1;

        return divisor;
    }
    
    /* Randomly generate a positive integer that is coprime to the given
     positive integer n and approximately in the range of [KEY_LOW_BOUND, n). */
    public static int genCoPrime(int n) {
        int copn = (int)(Math.random() * (n - KEY_LOW_BOUND)) + KEY_LOW_BOUND;
        if(n % 2 == 0) { // n is even, and is hence only coprime to odd numbers
            if(copn % 2 == 0)
                copn--;
            while(gcd(n, copn) != 1)
                copn -= 2;
        }
        else { // n is odd, and can be coprime to both odd and even numbers
            while(gcd(n, copn) != 1)
                copn--;
        }
        return copn;
    }

    /* Generate a public-private key pair and the corresponding modulus cipher.
     Returns a the key pair and the cipher.
     */
    public static RSAKeys genKeys() {
        int e, d;  // public key e for encryption, private key d for decryption
        int p, q;  // the two primes used to generate the keys

        int phi;	// the modulus
        e = d = p = q = 1;  // Delete this dummy line as you complete your code
        p = genPrime();
        q = genPrime();
        phi = (p - 1) * (q - 1); // euler totient
        // e*d = 1 mod phi.  e and d must be coprime to phi
        e = genCoPrime(phi);		
        // d = e^-1 mod phi -->  e*d - K*phi = 1 
        // find d using Extended Euclidean Algorithm:
        int D = 1, r = phi, R = e;
        d = 0;
        while (R != 0) {
        	int quotient = r / R;
        	int tempD = D, tempR = R;
        	D = d - quotient * tempD; d = tempD;
        	R = r - quotient * tempR; r = tempR;       	
        }	
        // now d is computed
        
        return new RSAKeys(e, d, p * q);
    }

    /* Find the remainder of pow(m, k) (i.e. m to the power of k) divided by c.
     m - the message text, a number in this project (> 0)
     k - the encryption/decryption key (> 0)
     c - the cipher p*q (> 0)
     This method is the actual encryption/decryption process. It is called by
     both methods 'encrypt' and 'decrypt'.
     */
    public static int powMod(int m, int k, int c) {
        int result = 1;

        m = m % c;	// reduce m 
        for (int i = 0; i < k; i++) // This runs in O(k)
        	result  = (result * m) % c;

        // TODO: use repeated squaring instead
        
        return result;
    }

    /* Encryption function
     Parameters:
     m - the original message, or plaintext (int, <= MAX_INPUT_MESSAGE)
     e - the public encryption key
     c - the modulus cipher p*q
     Returns:
     the encrypted message (i.e. ciphertext, which is an int)
     */
    public static int encrypt(int m, int e, int c) {
        // Catch some invalid inputs
        if(m < 0) {
            System.out.println("STOP: plaintext is a negative number!");
            System.exit(1);
        }
        if(m > MAX_INPUT_MESSAGE) {
            System.out.println("STOP: plaintext is too big! (max = " +
                               MAX_INPUT_MESSAGE + ")");
            return -1;
        }
        // Compute the ciphertext from original message using power-mod
        return powMod(m, e, c);
    }
    
    /* Decryption function
     Parameters:
     s - the encrypted message (i.e. ciphertext)
     d - the private decryption key
     c - the modulus cipher p*q
     Returns:
     the decrypted message, i.e. the original message (or plaintext, as an int)
     */
    public static int decrypt(int s, int d, int c) {
        // Catch some invalid inputs
        if(s < 0) {
            System.out.println("STOP: ciphertext is a negative number!" +
                             " -- Shouldn't happen.");
            System.exit(1);
        }
        if(s >= c) {
            System.out.println("STOP: ciphertext is not smaller than the cipher!" +
                               "\n-- Something is wrong.");
            return -1; // Just to make it more "Dr. Java friendly" -
                       // -- Should really be System.exit(1);
        }
        // decypting ciphertext to original message using power-mod
        return powMod(s, d, c);
    }

    /* Cracking function -- Recover the private decryption key d from the
     public encryption key e and modulus cipher c
     Parameters:
     e - the public encryption key
     c - the modulus cipher
     Returns:
     the private decryption key d
     */
    public static int crack(int e, int c) {
        /*factor the modulus cipher to obtain the two primes p and q that are used to
         generate the keys. Once p and q are known, one can find the
         private decryption key d from the public encryption key e in
         the same fashion as in genKeys. */
        int result = 1; 

        int p = -1, q = -1, d;
        // (x^e)^d = x^ed = x mod c
        // So by euler-fermat theorem: ed - 1 = 0 mod phi(c)
        // d = e^-1 mod phi(c) 
        // --->  e*d - K*phi = 1
  
        // 1. Need to find p,q to compute phi(c) = (p-1)*(q-1):
        // find a divisor of c:
        if(c % 2 == 0) p = 2;
        else {
        	// if c has divisor x then either x or c/x is <= sqrt(n)
        	// so we only look for divisors up to sqrt(c)
        	int sqrt = (int) Math.sqrt(c) + 1;	
        	for (int i = 3; i < sqrt; i += 2) {
				if (c % i == 0) {
					p = i;
					break;
				}
			}
        }
        q = c / p;
        int phi = (p - 1) * (q - 1);

        // 2. Now find d using Extended Euclidean Algorithm: 
        int D = 1, r = phi, R = e;
        d = 0;
        while (R != 0) {
        	int quotient = r / R;
        	int tempD = D, tempR = R;
        	D = d - quotient * tempD; d = tempD;
        	R = r - quotient * tempR; r = tempR;       	
        }	
        // now d is computed
      
        result = d;  

        return result;
    }

    public static void main(String[] args) {
    	
        final String usageMsg =
                "Usage: java RSA <mode> [args ...]\n" +
                "mode = <genkeys | enc | dec | crack>\n" +
                "args:\n" +
                "  genkeys - (no args)\n" +
                "  enc - m (plaintext), e (encryption key), c (modulus cipher)\n" +
                "  dec - s (ciphertext), d (decryption key), c (modulus cipher)\n" +
                "  crack - e (encryption key), c (modulus cipher)\n" +
                "addition modes to help debugging: <testprime | testgcd>\n" +
                "  testprime - n  (call your testPrime to test whether n is prime\n" +
                "  testgcd - a, b (call your gcd to find the gcd of a and b)\n" +
                "All arguments must be integers.\n" +
                "Examples:\n" +
                "  java RSA genkeys\n" +
                "  java RSA enc 123 17 3233\n";
        if(args.length < 1) {
            System.out.println(usageMsg);
            System.exit(1);
        }
        // Find the mode
        if(args[0].equalsIgnoreCase("genkeys")) {
            System.out.println("Generating keys...");
            RSAKeys keys = genKeys();
            System.out.println("--> Public encryption key e: " + keys.encKey +
                               "\n--> Private decryption key d: " + keys.decKey +
                               "\n--> Modulus cipher c: " + keys.cipher);
        }
        else if(args[0].equalsIgnoreCase("enc") ||
                args[0].equalsIgnoreCase("dec") ||
                args[0].equalsIgnoreCase("crack") ||
                args[0].equalsIgnoreCase("testprime") ||
                args[0].equalsIgnoreCase("testgcd")) {
            int[] input = new int[args.length];
            // Parsing the input arguments
            for (int i = 1; i < args.length; i++) {
                try { // try-catch required by method parseInt
                    input[i] = Integer.parseInt(args[i]);
                }
                catch (NumberFormatException e) {
                    System.out.println("***Argument " + i + ": " + args[i] +
                                       " is not an integer!");
                    System.exit(1);
                }
            }
            if(args[0].equalsIgnoreCase("enc")) {
                if(input.length < 4) { // Not enough arguments
                    System.out.println("***Too few arguments!\n" + usageMsg);
                    System.exit(1);
                }
                System.out.println("Plaintext m: " + input[1] +
                                   "\nEncryption key e: " + input[2] +
                                   "\nModulus cipher c: " + input[3] +
                                   "\nEncrypting...");
                int s = encrypt(input[1], input[2], input[3]);
                if(s != -1)  // -1 is the "error code"
                    System.out.println("--> Ciphertext s: " + s);
            }
            else if(args[0].equalsIgnoreCase("dec")) {
                if(input.length < 4) { // Not enough arguments
                    System.out.println("***Too few arguments!\n" + usageMsg);
                    System.exit(1);
                }
                System.out.println("Ciphertext s: " + input[1] +
                                   "\nDecryption key d: " + input[2] +
                                   "\nModulus cipher c: " + input[3] +
                                   "\nDecrypting...");
                int m = decrypt(input[1], input[2], input[3]);
                if(m != -1)  // -1 is the "error code"
                    System.out.println("--> Plaintext m: " + m);
            }
            else if(args[0].equalsIgnoreCase("crack")) {
                if(input.length < 3) { // Not enough arguments
                    System.out.println("***Too few arguments!\n" + usageMsg);
                    System.exit(1);
                }
                System.out.println("Encryption key e: " + input[1] +
                                   "\nModulus cipher c: " + input[2]);
                System.out.println("Cracking...");
                int d = crack(input[1], input[2]);
                System.out.println("--> Recovered decryption key d: " + d);
            }
            else if(args[0].equalsIgnoreCase("testprime")) {
                if(input.length < 2) { // Not enough arguments
                    System.out.println("***Too few arguments!\n" + usageMsg);
                    System.exit(1);
                }
                System.out.println("testPrime(" + input[1] + ") = " +
                                   testPrime(input[1]));
            }
            else if(args[0].equalsIgnoreCase("testgcd")) {
                if(input.length < 3) { // Not enough arguments
                    System.out.println("***Too few arguments!\n" + usageMsg);
                    System.exit(1);
                }
                System.out.println("gcd(" + input[1] + ", " + input[2] + ") = "
                                   + gcd(input[1], input[2]));
            }
        }
        else {
            System.out.println("***Unknown mode: " + args[0]);
            System.out.println(usageMsg);
            System.exit(1);
        }
    } //method main

} //class RSA


/*******************************
 A simple data structure storing a triplet: the public encryption key e,
 the private decryption key d, and the cipher c = p*q.
 ***/
class RSAKeys {
   int encKey, decKey, cipher;

   public RSAKeys(int e, int d, int c) {
       encKey = e;
       decKey = d;
       cipher = c;
   }
}
