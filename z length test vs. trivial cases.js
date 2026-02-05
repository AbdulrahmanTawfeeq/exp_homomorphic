// CRYPTOGRAPHIC SCHEME COMPREHENSIVE TESTER - BIGINT VERSION
// Paste this code in Chrome Console and run: testCryptoScheme(3) for 3-digit primes
//
// TERMINOLOGY CLARIFICATION:
// • TRIVIAL result: M^(ek+1) mod pk = M (bad for security - predictable)
// • NON-TRIVIAL result: M^(ek+1) mod pk ≠ M (good for security - unpredictable)
// 
// GOAL: Modified scheme should produce MORE non-trivial results than original scheme

// Utility Functions - BigInt versions
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
        const randomBigInt = BigInt(Math.floor(Math.random() * Number(range)));
        candidate = min + randomBigInt;
        if (candidate % 2n === 0n) candidate++; // Make odd
    } while (!isPrime(candidate));
    
    return candidate;
}

function secureRandomBigInt(min, max) {
    const minBI = BigInt(min);
    const maxBI = BigInt(max);
    const range = maxBI - minBI + 1n;
    const randomBI = BigInt(Math.floor(Math.random() * Number(range)));
    return minBI + randomBI;
}

function modPow(base, exp, mod) {
    const baseBI = BigInt(base);
    const expBI = BigInt(exp);
    const modBI = BigInt(mod);
    
    if (modBI === 1n) return 0n;
    let result = 1n;
    let baseMod = baseBI % modBI;
    let expCopy = expBI;
    
    while (expCopy > 0n) {
        if (expCopy % 2n === 1n) {
            result = (result * baseMod) % modBI;
        }
        expCopy = expCopy / 2n;
        baseMod = (baseMod * baseMod) % modBI;
    }
    return result;
}

function primeFactors(n) {
    const num = BigInt(n);
    if (num <= 1n) return {};
    const factors = {};
    let d = 2n;
    let remaining = num;
    
    while (d * d <= remaining) {
        while (remaining % d === 0n) {
            const key = d.toString();
            factors[key] = (factors[key] || 0) + 1;
            remaining = remaining / d;
        }
        d++;
    }
    if (remaining > 1n) {
        const key = remaining.toString();
        factors[key] = (factors[key] || 0) + 1;
    }
    return factors;
}

function gcd(a, b) {
    let aBI = BigInt(a);
    let bBI = BigInt(b);
    while (bBI !== 0n) {
        let temp = bBI;
        bBI = aBI % bBI;
        aBI = temp;
    }
    return aBI;
}

// Main Test Function
function testCryptoScheme(primeDigits, zMin = 10, zMax = 1000, wMin = 50, wMax = 5000, sampleLimit = 5000) {
    console.log(`\n🔒 CRYPTOGRAPHIC SCHEME TEST - ${primeDigits}-DIGIT PRIMES (BigInt)`);
    console.log("=".repeat(60));
    
    // Generate p and q as BigInt
    const p = generatePrime(primeDigits);
    const q = generatePrime(primeDigits);
    const n = p * q;
    const phiN = (p - 1n) * (q - 1n);
    
    console.log(`📊 Parameters: p=${p}, q=${q}, n=${n}, φ(n)=${phiN}`);
    console.log(`🔧 Random ranges: z=[${zMin},${zMax}], w=[${wMin},${wMax}]`);
    console.log(`🎯 Testing messages with sample limit: ${sampleLimit}`);
    
    const maxPkEstimate = n * BigInt(zMax);
    const shouldSample = sampleLimit > 10000;
    const testLimit = shouldSample ? sampleLimit : Math.min(Number(maxPkEstimate > 10000n ? 10000n : maxPkEstimate), 10000);
    
    if (shouldSample) {
        console.log(`⚠️  Using sampling strategy with ${testLimit} test cases`);
    } else {
        console.log(`✅ Testing exhaustively up to ${testLimit}`);
    }
    
    let totalTests = 0;
    let origNonTrivialCount = 0;
    let modNonTrivialCount = 0;
    let modificationFailures = [];
    let allOriginalTrivialCases = [];
    let samples = [];
    
    // Testing single message
    function testMessage(m) {
        const mBI = BigInt(m);
        const z = secureRandomBigInt(zMin, zMax);
        const w = secureRandomBigInt(wMin, wMax);
        const pkOrig = n * z;
        const ek = w * phiN;
        
        const resultOrig = modPow(mBI, ek + 1n, pkOrig);
        const origNonTrivial = (resultOrig !== mBI);
        
        const mFactors = primeFactors(mBI);
        const primes = Object.keys(mFactors).map(key => BigInt(key));
        
        let modNonTrivial = false;
        let resultMod = null;
        let zPrime = z;
        let pkMod = pkOrig;
        let p1 = null, a1 = null;
        
        if (primes.length > 0) {
            p1 = primes[0];
            a1 = BigInt(mFactors[p1.toString()]);
            zPrime = z * (p1 ** (a1 + 1n));
            pkMod = n * zPrime;
            resultMod = modPow(mBI, ek + 1n, pkMod);
            modNonTrivial = (resultMod !== mBI);
        } else {
            resultMod = "N/A";
            modNonTrivial = true;
        }
        
        return {
            m: mBI, z, w, pkOrig, pkMod, ek,
            resultOrig, origNonTrivial,
            resultMod, modNonTrivial,
            mFactors, p1, a1, zPrime
        };
    }

    // Helper to print detailed case info including params
    function printCaseWithParams(sample, indexLabel) {
        const factorStr = Object.entries(sample.mFactors)
            .map(([p, e]) => e > 1 ? `${p}^${e}` : p)
            .join('×') || '1';
        
        console.log(`${indexLabel}. M=${sample.m} (${factorStr})`);
        console.log(`   🔴 Original TRIVIAL: M^(ek+1) mod pk = ${sample.resultOrig} = M`);
        console.log(`   ▶︎ Original params: z=${sample.z}, w=${sample.w}, ek=${sample.ek}, pk=${sample.pkOrig}`);
        
        if (sample.resultMod !== "N/A") {
            const modStatus = sample.modNonTrivial ? '✅ FIXED' : '🔴 STILL TRIVIAL';
            console.log(`   Modified: M^(ek+1) mod pk = ${sample.resultMod} ${modStatus}`);
            console.log(`   ▶︎ Modified params: z'=${sample.zPrime} ${sample.p1 ? `(z' = z * ${sample.p1}^(a1+1), a1=${sample.a1})` : ''}, w=${sample.w}, ek=${sample.ek}, pk=${sample.pkMod}`);
        } else {
            console.log(`   Modified: N/A (m=1 special case)`);
        }
        console.log('');
    }
    
    console.log(`\n🧪 Starting tests...`);
    const startTime = Date.now();
    
    const testMax = Math.min(testLimit, 10000);
    for (let m = 1; m <= testMax; m++) {
        const result = testMessage(m);
        totalTests++;
        
        if (result.origNonTrivial) origNonTrivialCount++;
        if (result.modNonTrivial) modNonTrivialCount++;
        
        if (!result.origNonTrivial) {
            allOriginalTrivialCases.push(result);
        }
        if (!result.modNonTrivial && BigInt(m) > 1n) {
            modificationFailures.push(result);
        }
        if (samples.length < 15) {
            samples.push(result);
        }
        if (m % 1000 === 0) {
            console.log(`   ... tested ${m} values`);
        }
    }
    
    const endTime = Date.now();
    const duration = (endTime - startTime) / 1000;
    
    console.log(`\n📈 RESULTS SUMMARY`);
    console.log("-".repeat(40));
    console.log(`⏱️  Test duration: ${duration.toFixed(2)}s`);
    console.log(`🔢 Total tests: ${totalTests}`);
    console.log(`📊 Original scheme non-trivial: ${origNonTrivialCount}/${totalTests} (${(origNonTrivialCount/totalTests*100).toFixed(1)}%)`);
    console.log(`🎯 Modified scheme non-trivial: ${modNonTrivialCount}/${totalTests} (${(modNonTrivialCount/totalTests*100).toFixed(1)}%)`);
    console.log(`❌ Modification failures: ${modificationFailures.length}`);
    console.log(`📈 Improvement: +${((modNonTrivialCount-origNonTrivialCount)/totalTests*100).toFixed(1)}% more non-trivial cases`);
    
    const origTrivialCount = totalTests - origNonTrivialCount;
    const modTrivialCount = totalTests - modNonTrivialCount;
    console.log(`\n🔍 DETAILED BREAKDOWN:`);
    console.log(`Original scheme: ${origTrivialCount} trivial (bad), ${origNonTrivialCount} non-trivial (good)`);
    console.log(`Modified scheme: ${modTrivialCount} trivial (bad), ${modNonTrivialCount} non-trivial (good)`);
    
    console.log(`\n🔍 ALL ORIGINAL SCHEME TRIVIAL CASES (${allOriginalTrivialCases.length} TOTAL):`);
    if (allOriginalTrivialCases.length === 0) {
        console.log(`✅ NO TRIVIAL CASES found in original scheme - Perfect!`);
    } else {
        console.log(`⚠️  Found ${allOriginalTrivialCases.length} trivial cases in original scheme:`);
        console.log(`=`.repeat(60));
        
        const detailedCount = Math.min(20, allOriginalTrivialCases.length);
        const summaryCount = allOriginalTrivialCases.length - detailedCount;
        
        allOriginalTrivialCases.slice(0, detailedCount).forEach((sample, i) => {
            printCaseWithParams(sample, i + 1);
        });
        
        if (summaryCount > 0) {
            console.log(`... and ${summaryCount} more trivial cases (showing first ${detailedCount} only)`);
            console.log('');
        }
    }
    
    if (modificationFailures.length > 0) {
        console.log(`\n🚨 MODIFICATION FAILURES (${modificationFailures.length} CASES):`);
        console.log(`Cases where BOTH original AND modified schemes were trivial:`);
        console.log(`=`.repeat(60));
        modificationFailures.forEach((fail, i) => {
            printCaseWithParams(fail, i + 1);
        });
    } else {
        console.log(`\n🎉 PERFECT MODIFICATION: All original trivial cases were FIXED!`);
        console.log(`Modified scheme converted all ${allOriginalTrivialCases.length} trivial cases to non-trivial.`);
    }
    
    const modificationSuccess = (modNonTrivialCount / totalTests) * 100;
    const improvement = modNonTrivialCount - origNonTrivialCount;
    
    console.log(`\n🏆 FINAL VERDICT:`);
    console.log(`${modificationSuccess >= 95 ? '✅' : '❌'} Modified scheme non-trivial rate: ${modificationSuccess.toFixed(2)}%`);
    console.log(`${improvement > 0 ? '✅' : '❌'} Improvement over original: +${improvement} cases (${((improvement/totalTests)*100).toFixed(1)}%)`);
    console.log(`${modificationFailures.length === 0 ? '✅' : '❌'} Zero modification failures: ${modificationFailures.length === 0}`);
    console.log(`🔒 Modification ${modificationSuccess >= 95 && improvement > totalTests*0.1 ? 'SUCCESSFUL' : 'NEEDS_REVIEW'} for ${primeDigits}-digit primes`);
    
    return {
        primeDigits, p, q, totalTests,
        origNonTrivialCount, modNonTrivialCount,
        failures: modificationFailures.length,
        successRate: modificationSuccess,
        improvement, duration
    };
}

// Batch testing function remains unchanged
function runBatchTests(primeDigits, runs = 3, zMin = 10, zMax = 1000, wMin = 50, wMax = 5000, sampleLimit = 5000) {
    console.log(`\n🚀 BATCH TESTING: ${runs} runs with ${primeDigits}-digit primes (BigInt)`);
    console.log("=".repeat(60));
    console.log(`🔧 Parameters: z=[${zMin},${zMax}], w=[${wMin},${wMax}], samples=${sampleLimit}`);
    
    const results = [];
    for (let i = 1; i <= runs; i++) {
        console.log(`\n--- RUN ${i}/${runs} ---`);
        const result = testCryptoScheme(primeDigits, zMin, zMax, wMin, wMax, sampleLimit);
        results.push(result);
    }
    
    const avgModSuccess = results.reduce((sum, r) => sum + r.successRate, 0) / runs;
    const totalFailures = results.reduce((sum, r) => sum + r.failures, 0);
    const totalImprovement = results.reduce((sum, r) => sum + r.improvement, 0);
    const totalDuration = results.reduce((sum, r) => sum + r.duration, 0);
    const totalTests = results.reduce((sum, r) => sum + r.totalTests, 0);
    const avgImprovement = totalImprovement / runs;
    
    console.log(`\n🎯 BATCH SUMMARY:`);
    console.log(`Total tests across all runs: ${totalTests}`);
    console.log(`Average modified scheme success: ${avgModSuccess.toFixed(2)}%`);
    console.log(`Average improvement per run: +${avgImprovement.toFixed(0)} cases`);
    console.log(`Total modification failures: ${totalFailures}`);
    console.log(`Total duration: ${totalDuration.toFixed(2)}s`);
    console.log(`Average per run: ${(totalDuration/runs).toFixed(2)}s`);
    console.log(`Modification consistently effective: ${avgModSuccess >= 95 && avgImprovement > 0 ? '✅ YES' : '❌ NO'}`);
    
    return results;
}
