package exponentialHE;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.io.*;

public class HomomorphicEncryptionBenchmark {
    
    private static final SecureRandom random = new SecureRandom();
    private static final int WARMUP_ITERATIONS = 20;
    private static final int TEST_ITERATIONS = 5000;
    private static final int ROUNDS = 10;
    private static final int P_BITS = 512;
    private static final int Q_BITS = 512;
    private static final int Z_BITS = 512;
    
    // Statistical results storage
    static class BenchmarkResults {
        List<Double> oldTimes = new ArrayList<>();
        List<Double> newTimes = new ArrayList<>();
        List<Double> oldDecryptTimes = new ArrayList<>();
        List<Double> newDecryptTimes = new ArrayList<>();
        List<Double> lambdaPhiRatios = new ArrayList<>();
        List<Integer> oldSizes = new ArrayList<>();
        List<Integer> newSizes = new ArrayList<>();
        
        void addRound(double oldTime, double newTime, 
                     double oldDecryptTime, double newDecryptTime,
                     double ratio, int oldSize, int newSize) {
            oldTimes.add(oldTime);
            newTimes.add(newTime);
            oldDecryptTimes.add(oldDecryptTime);
            newDecryptTimes.add(newDecryptTime);
            lambdaPhiRatios.add(ratio);
            oldSizes.add(oldSize);
            newSizes.add(newSize);
        }
        
        double mean(List<Double> values) {
            return values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        }
        
        double meanInt(List<Integer> values) {
            return values.stream().mapToInt(Integer::intValue).average().orElse(0.0);
        }
        
        double stdDev(List<Double> values) {
            double mean = mean(values);
            double variance = values.stream()
                .mapToDouble(v -> Math.pow(v - mean, 2))
                .average().orElse(0.0);
            return Math.sqrt(variance);
        }
        
        double stdDevInt(List<Integer> values) {
            double mean = meanInt(values);
            double variance = values.stream()
                .mapToInt(v -> (int)Math.pow(v - mean, 2))
                .average().orElse(0.0);
            return Math.sqrt(variance);
        }
    }
    
    // Scheme parameters
    static class SchemeParameters {
        BigInteger p, q, n;
        BigInteger phiN, lambdaN;
        BigInteger pHalf;  // Precomputed p/2
        double lambdaPhiRatio;
        
        SchemeParameters(int pBits, int qBits) {
            this.p = BigInteger.probablePrime(pBits, random);
            this.q = BigInteger.probablePrime(qBits, random);
            this.n = p.multiply(q);
            
            BigInteger pMinus1 = p.subtract(BigInteger.ONE);
            BigInteger qMinus1 = q.subtract(BigInteger.ONE);
            
            this.phiN = pMinus1.multiply(qMinus1);
            this.lambdaN = lcm(pMinus1, qMinus1);
            this.lambdaPhiRatio = lambdaN.doubleValue() / phiN.doubleValue();
            
            // Precompute p/2 for optimized decryption
            this.pHalf = p.shiftRight(1);  // Bit shift instead of divide(TWO)
        }
    }
    
    // Encryption result
    static class EncryptionResult {
        BigInteger ciphertext;
        BigInteger decrypted;
        long encryptTimeNanos;
        long decryptTimeNanos;
        int rejections;
        int ciphertextBits;
        boolean correct;
        
        EncryptionResult(BigInteger c, BigInteger d, long encTime, long decTime, int rej, boolean isCorrect) {
            this.ciphertext = c;
            this.decrypted = d;
            this.encryptTimeNanos = encTime;
            this.decryptTimeNanos = decTime;
            this.rejections = rej;
            this.ciphertextBits = c.bitLength();
            this.correct = isCorrect;
        }
    }
    
    // OLD Scheme
    static EncryptionResult oldEncrypt(BigInteger message, SchemeParameters params) {
        long encStart = System.nanoTime();
        
        BigInteger z = BigInteger.probablePrime(Z_BITS, random);
        BigInteger pk = params.p.multiply(z);
        BigInteger w = new BigInteger(32, random).add(BigInteger.ONE);
        BigInteger ek = w.multiply(params.phiN);
        BigInteger exponent = ek.add(BigInteger.ONE);
        
        BigInteger ciphertext = message.modPow(exponent, pk);
        long encElapsed = System.nanoTime() - encStart;
        
        // Decrypt: M = C mod n
        long decStart = System.nanoTime();
        BigInteger decrypted = ciphertext.mod(params.p);
        long decElapsed = System.nanoTime() - decStart;
        
        boolean correct = decrypted.equals(message);
        
        return new EncryptionResult(ciphertext, decrypted, encElapsed, decElapsed, 0, correct);
    }
    
    // NEW Scheme
    static EncryptionResult newEncrypt(BigInteger message, SchemeParameters params) {
        long encStart = System.nanoTime();
        int rejections = 0;
        BigInteger ciphertext = null;
        
        for (int attempts = 0; attempts < 100; attempts++) {
            // Generate random z (not necessarily prime)
            BigInteger z = new BigInteger(Z_BITS, random);
            if (z.compareTo(BigInteger.ONE) <= 0) {
                z = z.add(BigInteger.TWO);
            }
            
            BigInteger w = new BigInteger(32, random).add(BigInteger.ONE);
            BigInteger ek = w.multiply(params.lambdaN);
            BigInteger exponent = ek.add(BigInteger.ONE);
            BigInteger pk = params.p.multiply(z);
            
            ciphertext = message.modPow(exponent, pk);
            
            // Validate: C ≠ M
            if (!ciphertext.equals(message)) {
                break;
            }
            rejections++;
        }
        long encElapsed = System.nanoTime() - encStart;
        
        // Decrypt: M = C - p * round(C/p)
        // Optimized: Use mod instead of division
        // If (C mod p) < p/2, then round(C/p) = floor(C/p), so M = C mod p
        // If (C mod p) >= p/2, then round(C/p) = ceil(C/p), so M = (C mod p) - p
        long decStart = System.nanoTime();
        BigInteger remainder = ciphertext.mod(params.p);
        BigInteger decrypted;
        if (remainder.compareTo(params.pHalf) < 0) {
            decrypted = remainder;  // First half: use mod directly
        } else {
            decrypted = remainder.subtract(params.p);  // Second half: centered remainder
        }
        long decElapsed = System.nanoTime() - decStart;
        
        boolean correct = decrypted.equals(message);
        
        return new EncryptionResult(ciphertext, decrypted, encElapsed, decElapsed, rejections, correct);
    }
    
    // Utility: LCM
    static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }
    
    // Run single round of tests
    static void runRound(int roundNum, SchemeParameters params, BenchmarkResults results) {
        
        List<Long> oldEncTimes = new ArrayList<>();
        List<Long> newEncTimes = new ArrayList<>();
        List<Long> oldDecTimes = new ArrayList<>();
        List<Long> newDecTimes = new ArrayList<>();
        List<Integer> oldSizes = new ArrayList<>();
        List<Integer> newSizes = new ArrayList<>();
        int oldErrors = 0;
        int newErrors = 0;
        
        // Perform encryptions
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            // Generate random message for this iteration (10 to 32 bits)
            int messageBits = 8 + random.nextInt(23); // 10 to 32 inclusive
            BigInteger message = new BigInteger(messageBits, random);
            
            // Randomize order to avoid bias
            List<Integer> order = Arrays.asList(0, 1);
            Collections.shuffle(order);
            
            for (int scheme : order) {
                switch (scheme) {
                    case 0:
                        EncryptionResult oldResult = oldEncrypt(message, params);
                        oldEncTimes.add(oldResult.encryptTimeNanos);
                        oldDecTimes.add(oldResult.decryptTimeNanos);
                        oldSizes.add(oldResult.ciphertextBits);
                        if (!oldResult.correct) oldErrors++;
                        break;
                    case 1:
                        EncryptionResult newResult = newEncrypt(message, params);
                        newEncTimes.add(newResult.encryptTimeNanos);
                        newDecTimes.add(newResult.decryptTimeNanos);
                        newSizes.add(newResult.ciphertextBits);
                        if (!newResult.correct) newErrors++;
                        break;
                }
            }
        }
        
        // Calculate averages
        double avgOldEnc = oldEncTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
        double avgNewEnc = newEncTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
        double avgOldDec = oldDecTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
        double avgNewDec = newDecTimes.stream().mapToLong(Long::longValue).average().orElse(0.0) / 1_000_000.0;
        int avgOldSize = (int) oldSizes.stream().mapToInt(Integer::intValue).average().orElse(0.0);
        int avgNewSize = (int) newSizes.stream().mapToInt(Integer::intValue).average().orElse(0.0);
        
        results.addRound(avgOldEnc, avgNewEnc, avgOldDec, avgNewDec, params.lambdaPhiRatio, avgOldSize, avgNewSize);
        
        double encSpeedup = ((avgOldEnc - avgNewEnc) / avgOldEnc) * 100.0;
        double decSpeedup = ((avgOldDec - avgNewDec) / avgOldDec) * 100.0;
        double sizeReduction = ((double)(avgOldSize - avgNewSize) / avgOldSize) * 100.0;
        
        System.out.printf("Round %2d: λ/φ=%.4f | OLD: Enc=%.4fms Dec=%.6fms (%4db) | NEW: Enc=%.4fms Dec=%.6fms (%4db) | EncΔ:%+.1f%% DecΔ:%+.1f%% SizeΔ:%.1f%%",
            roundNum, params.lambdaPhiRatio, avgOldEnc, avgOldDec, avgOldSize, avgNewEnc, avgNewDec, avgNewSize, encSpeedup, decSpeedup, sizeReduction);
        
        if (oldErrors > 0 || newErrors > 0) {
            System.out.printf(" [ERRORS: OLD=%d NEW=%d]", oldErrors, newErrors);
        }
        System.out.println();
    }
    
    // Main benchmark execution
    public static void main(String[] args) throws IOException {
        System.out.println("═══════════════════════════════════════════════════════════════════════════");
        System.out.println("  Formal Benchmark: Homomorphic Encryption Scheme Comparison");
        System.out.println("  (Performance + Storage Analysis)");
        System.out.println("═══════════════════════════════════════════════════════════════════════════\n");
        
        System.out.println("Configuration:");
        System.out.println("  Prime sizes: p=" + P_BITS + " bits, q=" + Q_BITS + " bits");
        System.out.println("  Random z size: " + Z_BITS + " bits");
        System.out.println("  Message size: 8-32 bits (random per encryption)");
        System.out.println("  Warmup iterations: " + WARMUP_ITERATIONS);
        System.out.println("  Test iterations per round: " + TEST_ITERATIONS);
        System.out.println("  Number of rounds: " + ROUNDS);
        System.out.println("  Total operations: " + (ROUNDS * TEST_ITERATIONS * 2) + " encryptions + " + (ROUNDS * TEST_ITERATIONS * 2) + " decryptions\n");
        
        BenchmarkResults results = new BenchmarkResults();
        
        // Warmup phase
        System.out.println("Phase 1: JVM Warmup (" + WARMUP_ITERATIONS + " iterations)...");
        SchemeParameters warmupParams = new SchemeParameters(P_BITS, Q_BITS);
        BigInteger warmupMessage = BigInteger.valueOf(12345);
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            oldEncrypt(warmupMessage, warmupParams);
            newEncrypt(warmupMessage, warmupParams);
        }
        System.out.println("Warmup complete.\n");
        
        // Testing phase
        System.out.println("Phase 2: Benchmark Execution\n");
        for (int round = 1; round <= ROUNDS; round++) {
            SchemeParameters params = new SchemeParameters(P_BITS, Q_BITS);
            runRound(round, params, results);
        }
        
        // Statistical analysis
        System.out.println("\n═══════════════════════════════════════════════════════════════════════════");
        System.out.println("  Statistical Analysis");
        System.out.println("═══════════════════════════════════════════════════════════════════════════\n");
        
        double meanOldEnc = results.mean(results.oldTimes);
        double meanNewEnc = results.mean(results.newTimes);
        double meanOldDec = results.mean(results.oldDecryptTimes);
        double meanNewDec = results.mean(results.newDecryptTimes);
        
        double stdOldEnc = results.stdDev(results.oldTimes);
        double stdNewEnc = results.stdDev(results.newTimes);
        double stdOldDec = results.stdDev(results.oldDecryptTimes);
        double stdNewDec = results.stdDev(results.newDecryptTimes);
        
        double meanOldSize = results.meanInt(results.oldSizes);
        double meanNewSize = results.meanInt(results.newSizes);
        double stdOldSize = results.stdDevInt(results.oldSizes);
        double stdNewSize = results.stdDevInt(results.newSizes);
        
        double encSpeedup = ((meanOldEnc - meanNewEnc) / meanOldEnc) * 100.0;
        double decSpeedup = ((meanOldDec - meanNewDec) / meanOldDec) * 100.0;
        double sizeReduction = ((meanOldSize - meanNewSize) / meanOldSize) * 100.0;
        
        System.out.println("Encryption Time (milliseconds):\n");
        System.out.printf("  OLD Scheme:\n");
        System.out.printf("    Mean:    %.4f ms\n", meanOldEnc);
        System.out.printf("    Std Dev: %.4f ms\n", stdOldEnc);
        
        System.out.printf("  NEW Scheme:\n");
        System.out.printf("    Mean:    %.4f ms\n", meanNewEnc);
        System.out.printf("    Std Dev: %.4f ms\n", stdNewEnc);
        System.out.printf("    Speedup: %+.2f%%\n\n", encSpeedup);
        
        System.out.println("Decryption Time (milliseconds):\n");
        System.out.printf("  OLD Scheme:\n");
        System.out.printf("    Mean:    %.6f ms\n", meanOldDec);
        System.out.printf("    Std Dev: %.6f ms\n", stdOldDec);
        
        System.out.printf("  NEW Scheme:\n");
        System.out.printf("    Mean:    %.6f ms\n", meanNewDec);
        System.out.printf("    Std Dev: %.6f ms\n", stdNewDec);
        System.out.printf("    Speedup: %+.2f%%\n\n", decSpeedup);
        
        System.out.println("Ciphertext Size (bits):\n");
        System.out.printf("  OLD Scheme:\n");
        System.out.printf("    Mean:    %.1f bits (%.1f KB)\n", meanOldSize, meanOldSize/8192.0);
        System.out.printf("    Std Dev: %.2f bits\n", stdOldSize);
        
        System.out.printf("  NEW Scheme:\n");
        System.out.printf("    Mean:    %.1f bits (%.1f KB)\n", meanNewSize, meanNewSize/8192.0);
        System.out.printf("    Std Dev: %.2f bits\n", stdNewSize);
        System.out.printf("    Size Reduction: %.2f%%\n\n", sizeReduction);
        
        double meanLambdaPhi = results.mean(results.lambdaPhiRatios);
        double exponentReduction = (1.0 - meanLambdaPhi) * 100.0;
        
        System.out.println("Exponent Analysis:\n");
        System.out.printf("  Mean λ(n)/φ(n) ratio: %.4f\n", meanLambdaPhi);
        System.out.printf("  Average exponent reduction: %.1f%%\n\n", exponentReduction);
        
        // Storage savings calculation
        long oldTotalBytes = (long)(meanOldSize / 8.0);
        long newTotalBytes = (long)(meanNewSize / 8.0);
        long savedBytes = oldTotalBytes - newTotalBytes;
        
        System.out.println("Storage Impact (per 1M encryptions):\n");
        System.out.printf("  OLD Scheme: %.2f MB\n", (oldTotalBytes * 1_000_000.0) / (1024.0 * 1024.0));
        System.out.printf("  NEW Scheme: %.2f MB\n", (newTotalBytes * 1_000_000.0) / (1024.0 * 1024.0));
        System.out.printf("  Space Saved: %.2f MB (%.1f%% reduction)\n\n", 
            (savedBytes * 1_000_000.0) / (1024.0 * 1024.0), sizeReduction);
                
        // Summary
        System.out.println("\n═══════════════════════════════════════════════════════════════════════════");
        System.out.println("  Summary");
        System.out.println("═══════════════════════════════════════════════════════════════════════════\n");
        
        System.out.printf("NEW Scheme Improvements:\n");
        System.out.printf("  • Encryption Speed:  %+.1f%% faster\n", encSpeedup);
        System.out.printf("  • Decryption Speed:  %+.1f%% faster\n", decSpeedup);
        System.out.printf("  • Ciphertext Size:   %.1f%% smaller\n", sizeReduction);
        System.out.printf("  • Exponent Size:     %.1f%% reduction\n\n", exponentReduction);
        
        System.out.printf("Performance Ranking (Encryption Time):\n");
        System.out.printf("  1. NEW: %.4f ms (%+.1f%% vs OLD)\n", meanNewEnc, encSpeedup);
        System.out.printf("  2. OLD: %.4f ms (baseline)\n\n", meanOldEnc);
        
        System.out.printf("Performance Ranking (Decryption Time):\n");
        System.out.printf("  1. NEW: %.6f ms (%+.1f%% vs OLD)\n", meanNewDec, decSpeedup);
        System.out.printf("  2. OLD: %.6f ms (baseline)\n\n", meanOldDec);
        
        System.out.printf("Storage Efficiency Ranking (Ciphertext Size):\n");
        System.out.printf("  1. NEW: %.0f bits (%.1f%% reduction)\n", meanNewSize, sizeReduction);
        System.out.printf("  2. OLD: %.0f bits (baseline)\n\n", meanOldSize);
        
    }
    
}