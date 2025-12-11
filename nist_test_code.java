package rng;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.io.*;
import java.util.*;

public class AsyHomomorphicNIST {
    
    // ========== CONFIGURATION PARAMETERS ==========
    private static final int BIT_SIZE = 512;  // Change this for p, q bit size (256, 512, 1024, 2048, etc.)
    private static final int NUM_CIPHERTEXTS = 10000;  // Number of ciphertexts to generate
    private static final int MESSAGE_BIT_SIZE = 64;  // Bit size for message M (8, 16, 32, 64, etc.)
    private static final boolean ASCII_FORMAT = true;  // true = ASCII text (.txt), false = Binary (.bin)
    private static final String KEYS_FILE = "keys.bin";
    private static final String CIPHERTEXTS_FILE = ASCII_FORMAT ? "ciphertexts.txt" : "ciphertexts.bin";
    
    private static final SecureRandom random = new SecureRandom();
    
    // Fixed key components (generated once)
    private BigInteger p, q, n, lambda_n;
    
    // Per-encryption components (regenerated for each M)
    // w, z, ek, pk are generated fresh per encryption
    
    public static void main(String[] args) {
        try {
            AsyHomomorphicNIST crypto = new AsyHomomorphicNIST();
            
            System.out.println("=== Updated Homomorphic Encryption - NIST Test Generator ===");
            System.out.println("Configuration:");
            System.out.println("  Prime bit size (p, q): " + BIT_SIZE);
            System.out.println("  Message bit size (M): " + MESSAGE_BIT_SIZE);
            System.out.println("  Number of ciphertexts: " + NUM_CIPHERTEXTS);
            System.out.println();
            
            // Generate keys
            System.out.println("Step 1: Generating keys...");
            crypto.generateKeys();
            System.out.println("Keys generated successfully!");
            System.out.println();
            
            // Generate ciphertexts
            System.out.println("Step 2: Generating " + NUM_CIPHERTEXTS + " ciphertexts...");
            System.out.println("  Sample plaintext messages (M):");
            List<BigInteger> ciphertexts = crypto.generateCiphertexts(NUM_CIPHERTEXTS);
            System.out.println("Ciphertexts generated successfully!");
            System.out.println();
            
            // Calculate total bits
            int ciphertextBitSize = ciphertexts.get(0).bitLength();
            long totalBits = (long) ciphertextBitSize * NUM_CIPHERTEXTS;
            System.out.println("Statistics:");
            System.out.println("  Each ciphertext size: " + ciphertextBitSize + " bits");
            System.out.println("  Total bits generated: " + totalBits);
            System.out.println("  Enough for NIST (1,000,000 bits): " + (totalBits >= 1000000 ? "YES ✓" : "NO ✗"));
            System.out.println();
            
            // Export to binary files
            System.out.println("Step 3: Exporting to binary files...");
            crypto.exportKeys();
            crypto.exportCiphertexts(ciphertexts);
            System.out.println("Export completed!");
            System.out.println();
            
            System.out.println("Files created:");
            System.out.println("  " + KEYS_FILE + " - Key components");
            System.out.println("  " + CIPHERTEXTS_FILE + " - " + (ASCII_FORMAT ? "ASCII bitstream" : "Binary bitstream") + " for NIST testing");
            System.out.println();
            System.out.println("NIST STS Command (in Cygwin64):");
            System.out.println("  ./assess " + (totalBits / 10) + "");
            System.out.println("  Then enter number of bitstreams (e.g., 10)");
            System.out.println("  Choose format: [" + (ASCII_FORMAT ? "0] ASCII" : "1] Binary"));
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Generate fixed keys (p, q, n, λ(n)) - called once
     */
    public void generateKeys() {
        System.out.println("  Generating fixed primes p and q...");
        // Generate large primes p and q
        p = BigInteger.probablePrime(BIT_SIZE, random);
        q = BigInteger.probablePrime(BIT_SIZE, random);
        
        // Ensure p != q
        while (p.equals(q)) {
            q = BigInteger.probablePrime(BIT_SIZE, random);
        }
        
        System.out.println("  Calculating n = p * q...");
        // n = p * q
        n = p.multiply(q);
        
        System.out.println("  Calculating λ(n) = lcm(p-1, q-1)...");
        // λ(n) = lcm(p-1, q-1)
        BigInteger p_minus_1 = p.subtract(BigInteger.ONE);
        BigInteger q_minus_1 = q.subtract(BigInteger.ONE);
        lambda_n = lcm(p_minus_1, q_minus_1);
        
        System.out.println("  Fixed key generation completed!");
        System.out.println("    p bit length: " + p.bitLength());
        System.out.println("    q bit length: " + q.bitLength());
        System.out.println("    n bit length: " + n.bitLength());
        System.out.println("    λ(n) bit length: " + lambda_n.bitLength());
    }
    
    /**
     * Generate a valid z that satisfies all constraints
     */
    private BigInteger generateValidZ(BigInteger ek) {
        int maxAttempts = 100;
        int attempt = 0;
        
        while (attempt < maxAttempts) {
            // Generate a large prime z
            BigInteger z_candidate = BigInteger.probablePrime(BIT_SIZE, random);
            
            // Test with sample M values to check constraint: M^(ek+1) mod p*z ≠ M
            boolean isValid = true;
            BigInteger pz = p.multiply(z_candidate);
            BigInteger ek_plus_1 = ek.add(BigInteger.ONE);
            
            // Test with multiple M values
            for (int i = 0; i < 5; i++) {
                BigInteger M = generateRandomM();
                
                // Check gcd(M, z) = 1
                if (!M.gcd(z_candidate).equals(BigInteger.ONE)) {
                    isValid = false;
                    break;
                }
                
                // Check M^(ek+1) mod p*z ≠ M
                BigInteger test = M.modPow(ek_plus_1, pz);
                if (test.equals(M)) {
                    isValid = false;
                    break;
                }
            }
            
            if (isValid) {
                return z_candidate;
            }
            
            attempt++;
        }
        
        throw new RuntimeException("Could not find valid z after " + maxAttempts + " attempts");
    }
    
    /**
     * Generate random M in range [-p/2, p/2] excluding {-1, 0, 1}
     * M should be a practical small value for realistic encryption
     */
    private BigInteger generateRandomM() {
        BigInteger M;
        
        do {
            // Generate random value with specified bit size (practical message size)
            if (MESSAGE_BIT_SIZE <= 63) {
                // For smaller sizes, use long for efficiency
                long maxValue = (1L << MESSAGE_BIT_SIZE) - 1;
                long randomValue = Math.abs(random.nextLong()) % (maxValue + 1);
                
                // Randomly make it negative
                if (random.nextBoolean()) {
                    randomValue = -randomValue;
                }
                
                M = BigInteger.valueOf(randomValue);
            } else {
                // For larger sizes, use BigInteger
                M = new BigInteger(MESSAGE_BIT_SIZE, random);
                
                // Randomly make it negative
                if (random.nextBoolean()) {
                    M = M.negate();
                }
            }
            
            // Repeat if M is in {-1, 0, 1}
        } while (M.abs().compareTo(BigInteger.ONE) <= 0);
        
        // Verify M is within [-p/2, p/2]
        BigInteger p_half = p.divide(BigInteger.TWO);
        if (M.abs().compareTo(p_half) > 0) {
            // Shouldn't happen if MESSAGE_BIT_SIZE << BIT_SIZE
            throw new RuntimeException("M exceeds valid range [-p/2, p/2]. Reduce MESSAGE_BIT_SIZE.");
        }
        
        return M;
    }
    
    /**
     * Encrypt a message M with fresh w and z per encryption
     * C = M^(ek+1) mod p*z
     * where w and z are generated fresh for each encryption
     */
    public BigInteger encrypt(BigInteger M) {
        // Generate fresh w for this encryption
        BigInteger w = new BigInteger(BIT_SIZE, random);
        
        // Calculate ek = w * λ(n)
        BigInteger ek = w.multiply(lambda_n);
        
        // Generate fresh z (cryptographically secure prime) for this encryption
        BigInteger z = generateValidZ(ek);
        
        // Calculate p*z
        BigInteger pz = p.multiply(z);
        
        // Calculate ek+1
        BigInteger ek_plus_1 = ek.add(BigInteger.ONE);
        
        // C = M^(ek+1) mod p*z
        BigInteger C = M.modPow(ek_plus_1, pz);
//        System.out.println(C);
        return C;
    }
    
    /**
     * Decrypt a ciphertext C
     * M = C - p*round(C/p)
     */
    public BigInteger decrypt(BigInteger C) {
        // C/p as BigDecimal for precise division
        BigInteger quotient = C.divide(p);
        BigInteger remainder = C.mod(p);
        
        // Check if we need to round up (remainder >= p/2)
        if (remainder.multiply(BigInteger.TWO).compareTo(p) >= 0) {
            quotient = quotient.add(BigInteger.ONE);
        }
        
        // M = C - p*round(C/p)
        BigInteger M = C.subtract(p.multiply(quotient));
        
        return M;
    }
    
    /**
     * Generate multiple ciphertexts for NIST testing
     */
    public List<BigInteger> generateCiphertexts(int count) {
        List<BigInteger> ciphertexts = new ArrayList<>();
        
        for (int i = 0; i < count; i++) {
            // Generate random M for each encryption
            BigInteger M = generateRandomM();
            BigInteger C = encrypt(M);
            ciphertexts.add(C);
            
            // Print first 5 sample M values
            if (i < 5) {
                System.out.println("    M[" + i + "] = " + M);
            }
            
            if ((i + 1) % 1000 == 0) {
                System.out.println("    Generated " + (i + 1) + " ciphertexts...");
            }
        }
        
        return ciphertexts;
    }
    
    /**
     * Export fixed keys to binary file
     */
    public void exportKeys() throws IOException {
        try (DataOutputStream dos = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(KEYS_FILE)))) {
            
            writeVarLenBigInt(dos, p);
            writeVarLenBigInt(dos, q);
            writeVarLenBigInt(dos, n);
            writeVarLenBigInt(dos, lambda_n);
            
            System.out.println("  Fixed keys exported to " + KEYS_FILE);
            System.out.println("    (p, q, n, λ(n) only - w and z are generated fresh per encryption)");
        }
    }
    
    /**
     * Export ciphertexts as raw bitstream for NIST testing
     * Supports both ASCII (text) and Binary formats
     */
    public void exportCiphertexts(List<BigInteger> ciphertexts) throws IOException {
        if (ASCII_FORMAT) {
            exportCiphertextsASCII(ciphertexts);
        } else {
            exportCiphertextsBinary(ciphertexts);
        }
    }
    
    /**
     * Export ciphertexts as ASCII text file (0's and 1's)
     */
    private void exportCiphertextsASCII(List<BigInteger> ciphertexts) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(CIPHERTEXTS_FILE))) {
            
            // Find maximum bit length to normalize all ciphertexts
            int maxBitLength = 0;
            for (BigInteger c : ciphertexts) {
                maxBitLength = Math.max(maxBitLength, c.bitLength());
            }
            
            // Write each ciphertext as ASCII '0' and '1' characters
            for (BigInteger c : ciphertexts) {
                String bitString = c.toString(2); // Convert to binary string
                
                // Pad with leading zeros to normalize length
                while (bitString.length() < maxBitLength) {
                    bitString = "0" + bitString;
                }
                
                writer.write(bitString);
            }
            
            System.out.println("  Ciphertexts exported to " + CIPHERTEXTS_FILE + " (ASCII format)");
            System.out.println("  Each ciphertext normalized to " + maxBitLength + " bits");
            System.out.println("  File contains ASCII characters '0' and '1'");
        }
    }
    
    /**
     * Export ciphertexts as binary file (raw bytes)
     */
    private void exportCiphertextsBinary(List<BigInteger> ciphertexts) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(CIPHERTEXTS_FILE)))) {
            
            // Find maximum bit length to normalize all ciphertexts
            int maxBitLength = 0;
            for (BigInteger c : ciphertexts) {
                maxBitLength = Math.max(maxBitLength, c.bitLength());
            }
            
            // Pad to nearest byte
            int byteLength = (maxBitLength + 7) / 8;
            
            // Write each ciphertext as raw bytes (bitstream)
            for (BigInteger c : ciphertexts) {
                byte[] bytes = c.toByteArray();
                
                // Pad with leading zeros if needed
                if (bytes.length < byteLength) {
                    byte[] padded = new byte[byteLength];
                    System.arraycopy(bytes, 0, padded, byteLength - bytes.length, bytes.length);
                    bytes = padded;
                } else if (bytes.length > byteLength) {
                    // Remove sign byte if present
                    byte[] trimmed = new byte[byteLength];
                    System.arraycopy(bytes, bytes.length - byteLength, trimmed, 0, byteLength);
                    bytes = trimmed;
                }
                
                dos.write(bytes);
            }
            
            System.out.println("  Ciphertexts exported to " + CIPHERTEXTS_FILE + " (Binary format)");
            System.out.println("  Each ciphertext normalized to " + (byteLength * 8) + " bits");
        }
    }
    
    /**
     * Write variable-length BigInteger to stream
     */
    private void writeVarLenBigInt(DataOutputStream dos, BigInteger value) throws IOException {
        byte[] bytes = value.toByteArray();
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }
    
    /**
     * Calculate LCM of two BigIntegers
     */
    private BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }
}