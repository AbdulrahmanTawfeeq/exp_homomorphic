// =======================================================
// UPDATED CRYPTO SCHEME TESTER — WITH FAILURE CLASSIFICATION
// =======================================================

// ---------- Utilities ----------
function isPrime(n) {
    const num = BigInt(n);
    if (num < 2n) return false;
    if (num === 2n) return true;
    if (num % 2n === 0n) return false;
    for (let i = 3n; i * i <= num; i += 2n) {
        if (num % i === 0n) return false;
    }
    return true;
}

function generatePrime(digits) {
    const min = 10n ** BigInt(digits - 1);
    const max = 10n ** BigInt(digits) - 1n;
    let candidate;
    do {
        const range = max - min + 1n;
        const r = BigInt(Math.floor(Math.random() * Number(range)));
        candidate = min + r;
        if (candidate % 2n === 0n) candidate++;
    } while (!isPrime(candidate));
    return candidate;
}

function secureRandomBigInt(min, max) {
    const minBI = BigInt(min);
    const maxBI = BigInt(max);
    const range = maxBI - minBI + 1n;
    const r = BigInt(Math.floor(Math.random() * Number(range)));
    return minBI + r;
}

function modPow(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % mod;
        exp >>= 1n;
        base = (base * base) % mod;
    }
    return result;
}

// ---------- NEW: GCD Function ----------
function gcd(a, b) {
    a = BigInt(a);
    b = BigInt(b);
    while (b !== 0n) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// ---------- NEW: Multiplicative Order ----------
function multiplicativeOrder(base, mod) {
    base = BigInt(base);
    mod = BigInt(mod);
    
    if (gcd(base, mod) !== 1n) return null;
    
    let order = 1n;
    let current = base % mod;
    const maxIter = 100000n; // Prevent infinite loops
    
    while (current !== 1n && order < maxIter) {
        current = (current * base) % mod;
        order++;
    }
    
    return current === 1n ? order : null;
}

// ---------- NEW: Prime Factorization ----------
function primeFactorization(n) {
    n = BigInt(n);
    const factors = new Map();
    
    // Factor out 2s
    while (n % 2n === 0n) {
        factors.set(2n, (factors.get(2n) || 0n) + 1n);
        n /= 2n;
    }
    
    // Check odd factors
    let i = 3n;
    while (i * i <= n) {
        while (n % i === 0n) {
            factors.set(i, (factors.get(i) || 0n) + 1n);
            n /= i;
        }
        i += 2n;
    }
    
    if (n > 1n) factors.set(n, 1n);
    
    return factors;
}

// ---------- NEW: Classify Failure Case ----------
function classifyFailureCase(m, z, w, phiN) {
    const g = gcd(m, z);
    const ek = w * phiN;
    
    if (g === 1n) {
        // **CASE 1: gcd(M, z) = 1**
        const order = multiplicativeOrder(m, z);
        
        if (order === null) {
            return { case: 'unknown', subtype: 'order_computation_failed' };
        }
        
        if (ek % order === 0n) {
            return { 
                case: 1, 
                subtype: 'coprime_order_divides',
                details: `ord_z(M)=${order}, ek/ord=${ek/order}`
            };
        } else {
            return { case: 'unknown', subtype: 'coprime_order_not_divides' };
        }
    } else {
        // **CASE 2: gcd(M, z) > 1**
        const mFactors = primeFactorization(m);
        const zFactors = primeFactorization(z);
        
        let allPrimesAllowFailure = true;
        const primeResults = [];
        
        for (const [p, b] of zFactors) {
            if (mFactors.has(p)) {
                // Common prime
                const a = mFactors.get(p);
                const allowsFailure = a >= b;
                
                primeResults.push({
                    prime: p,
                    type: 'common',
                    a: a,
                    b: b,
                    allowsFailure: allowsFailure
                });
                
                if (!allowsFailure) allPrimesAllowFailure = false;
                
            } else {
                // Non-common prime (only in z)
                const order = multiplicativeOrder(m, p);
                
                if (order === null) {
                    primeResults.push({
                        prime: p,
                        type: 'non-common',
                        allowsFailure: 'unknown',
                        reason: 'order_failed'
                    });
                    continue;
                }
                
                const allowsFailure = (ek % order === 0n);
                
                primeResults.push({
                    prime: p,
                    type: 'non-common',
                    order: order,
                    allowsFailure: allowsFailure
                });
                
                if (!allowsFailure) allPrimesAllowFailure = false;
            }
        }
        
        if (allPrimesAllowFailure) {
            return { 
                case: 2, 
                subtype: 'all_primes_allow_failure',
                gcd: g,
                primeResults: primeResults
            };
        } else {
            return { 
                case: 'unknown', 
                subtype: 'not_all_primes_allow_failure',
                gcd: g,
                primeResults: primeResults
            };
        }
    }
}

// ---------- Main Test Function ----------
function testCryptoScheme(
    primeDigits,
    mMin,
    mMax,
    zMin,
    zMax,
    wMin,
    wMax,
    sampleLimit = 10000
) {
    console.log("\n🔒 CRYPTO SCHEME WITH FAILURE CLASSIFICATION");
    console.log("=".repeat(70));
    
    const p = generatePrime(primeDigits);
    const q = generatePrime(primeDigits);
    const n = p * q;
    const phiN = (p - 1n) * (q - 1n);
    
    console.log(`📊 p=${p}`);
    console.log(`📊 q=${q}`);
    console.log(`📊 n=${n}`);
    console.log(`📊 φ(n)=${phiN}`);
    
    console.log(`\n🎯 Sampling configuration:`);
    console.log(`M ∈ [${mMin}, ${mMax}]`);
    console.log(`z ∈ [${zMin}, ${zMax}]`);
    console.log(`w ∈ [${wMin}, ${wMax}]`);
    console.log(`Samples: ${sampleLimit}`);
    
    let totalTests = 0;
    let nonTrivialCount = 0;
    let case1Count = 0;
    let case2Count = 0;
    let unknownCount = 0;
    
    let case1Examples = [];
    let case2Examples = [];
    let unknownExamples = [];  // ✨ NEW: Track unknown cases
    
    console.log(`\n🧪 Starting tests with failure classification...`);
    const startTime = Date.now();
    
    while (totalTests < sampleLimit) {
        const m = secureRandomBigInt(mMin, mMax);
        const z = secureRandomBigInt(zMin, zMax);
        const w = secureRandomBigInt(wMin, wMax);
        
        const pk = n * z;
        const ek = w * phiN;
        const result = modPow(m, ek + 1n, pk);
        
        if (result !== m) {
            nonTrivialCount++;
        } else {
            // FAILURE DETECTED - Classify it
            const classification = classifyFailureCase(m, z, w, phiN);
            
            if (classification.case === 1) {
                case1Count++;
                if (case1Examples.length < 5) {
                    case1Examples.push({ m, z, w, ...classification });
                }
            } else if (classification.case === 2) {
                case2Count++;
                if (case2Examples.length < 5) {
                    case2Examples.push({ m, z, w, ...classification });
                }
            } else {
                unknownCount++;
                // ✨ NEW: Capture unknown cases with full details
                if (unknownExamples.length < 10) {
                    unknownExamples.push({ 
                        m, 
                        z, 
                        w, 
                        ek,
                        gcd: gcd(m, z),
                        ...classification 
                    });
                }
            }
        }
        
        totalTests++;
        if (totalTests % 1000 === 0) {
            console.log(`   ... tested ${totalTests}/${sampleLimit} samples`);
        }
    }
    
    const duration = (Date.now() - startTime) / 1000;
    const trivialCount = totalTests - nonTrivialCount;
    const successRate = (nonTrivialCount / totalTests) * 100;
    
    console.log(`\n📈 RESULTS SUMMARY`);
    console.log("-".repeat(70));
    console.log(`⏱️  Duration: ${duration.toFixed(2)}s`);
    console.log(`🔢 Total samples: ${totalTests}`);
    console.log(`✅ Non-trivial (SUCCESS): ${nonTrivialCount} (${successRate.toFixed(4)}%)`);
    console.log(`❌ Trivial (FAILURE): ${trivialCount} (${((trivialCount/totalTests)*100).toFixed(4)}%)`);
    
    console.log(`\n🔍 FAILURE BREAKDOWN:`);
    console.log(`   Case 1 (gcd=1, order divides): ${case1Count} (${((case1Count/trivialCount)*100).toFixed(2)}% of failures)`);
    console.log(`   Case 2 (gcd>1, all primes bad): ${case2Count} (${((case2Count/trivialCount)*100).toFixed(2)}% of failures)`);
    console.log(`   Unknown/Other: ${unknownCount} (${((unknownCount/trivialCount)*100).toFixed(2)}% of failures)`);
    
    // Determine which case is more dangerous
    console.log(`\n⚠️  DANGER ASSESSMENT:`);
    if (case1Count > case2Count) {
        console.log(`   🚨 Case 1 is DOMINANT (${((case1Count/case2Count).toFixed(2))}x more common)`);
        console.log(`   → Coprime M,z with order alignment is the primary weakness`);
    } else if (case2Count > case1Count) {
        console.log(`   🚨 Case 2 is DOMINANT (${((case2Count/case1Count).toFixed(2))}x more common)`);
        console.log(`   → Shared factors between M,z is the primary weakness`);
    } else {
        console.log(`   ⚖️  Both cases are equally dangerous`);
    }
    
    // Show examples
    if (case1Examples.length > 0) {
        console.log(`\n📋 CASE 1 Examples (first ${Math.min(5, case1Examples.length)}):`);
        case1Examples.forEach((ex, i) => {
            console.log(`   ${i+1}. M=${ex.m}, z=${ex.z}, w=${ex.w}`);
            console.log(`      ${ex.details}`);
        });
    }
    
    if (case2Examples.length > 0) {
        console.log(`\n📋 CASE 2 Examples (first ${Math.min(5, case2Examples.length)}):`);
        case2Examples.forEach((ex, i) => {
            console.log(`   ${i+1}. M=${ex.m}, z=${ex.z}, w=${ex.w}, gcd=${ex.gcd}`);
            if (ex.primeResults) {
                ex.primeResults.forEach(pr => {
                    if (pr.type === 'common') {
                        console.log(`      Prime ${pr.prime}: a=${pr.a}, b=${pr.b} → ${pr.allowsFailure ? '✓ allows' : '✗ prevents'}`);
                    } else {
                        console.log(`      Prime ${pr.prime}: ord=${pr.order} → ${pr.allowsFailure ? '✓ allows' : '✗ prevents'}`);
                    }
                });
            }
        });
    }
    
    // ✨ NEW: Display unknown cases
    if (unknownExamples.length > 0) {
        console.log(`\n❓ UNKNOWN Cases (first ${Math.min(10, unknownExamples.length)}):`);
        unknownExamples.forEach((ex, i) => {
            console.log(`\n   ${i+1}. M=${ex.m}, z=${ex.z}, w=${ex.w}`);
            console.log(`      gcd(M,z) = ${ex.gcd}`);
            console.log(`      Subtype: ${ex.subtype}`);
            console.log(`      Case: ${ex.case}`);
            
            if (ex.details) {
                console.log(`      Details: ${ex.details}`);
            }
            
            if (ex.primeResults) {
                console.log(`      Prime analysis:`);
                ex.primeResults.forEach(pr => {
                    if (pr.type === 'common') {
                        console.log(`         Prime ${pr.prime} (common): a=${pr.a}, b=${pr.b} → ${pr.allowsFailure ? '✓ allows' : '✗ prevents'}`);
                    } else if (pr.type === 'non-common') {
                        if (pr.allowsFailure === 'unknown') {
                            console.log(`         Prime ${pr.prime} (non-common): ${pr.reason}`);
                        } else {
                            console.log(`         Prime ${pr.prime} (non-common): ord=${pr.order} → ${pr.allowsFailure ? '✓ allows' : '✗ prevents'}`);
                        }
                    }
                });
            }
            
            if (ex.reason) {
                console.log(`      Reason: ${ex.reason}`);
            }
        });
    }
    
    return {
        primeDigits,
        totalTests,
        nonTrivialCount,
        trivialCount,
        case1Count,
        case2Count,
        unknownCount,
        successRate,
        duration,
        unknownExamples  // ✨ NEW: Return for further analysis
    };
}

testCryptoScheme(
    18,          // prime digits
    2, 1e18,    // M range
    1e12, 1e14,    // z range
    1e12, 1e14,  // w range
    100000       // samples
);

testCryptoScheme(
    18,          // prime digits
    2, 255,    // M range
    1e17, 1e18,    // z range
    1e17, 1e18,  // w range
    300000       // samples
);