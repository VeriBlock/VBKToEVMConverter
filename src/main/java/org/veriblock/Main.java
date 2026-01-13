package org.veriblock;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.Console;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;

public class Main {
    // Ledger data: maps VBK address to balance in atomic units
    private static Map<String, BigInteger> ledgerBalances = new HashMap<>();
    private static long ledgerBlockHeight = 0;

    // VBK uses 8 decimal places
    private static final BigDecimal VBK_DIVISOR = new BigDecimal("100000000");

    public static void main(String[] args) throws Exception {
        // 0) Provider
        Security.addProvider(new BouncyCastleProvider());

        // Load ledger data
        loadLedger();

        System.out.println("================================================================================");
        System.out.println("           VBK-to-EVM Address Converter and Registration Helper");
        System.out.println("================================================================================\n");
        System.out.println("This tool takes a raw VeriBlock private key, converts it to an EVM private key,");
        System.out.println("and provides you with a signed message for registration.\n");
        System.out.println("You can receive your rewards to either:");
        System.out.println("  - The EVM address equivalent to your VeriBlock address, OR");
        System.out.println("  - A separate EVM address of your choice\n");
        System.out.println("SECURITY WARNING: Since you are entering your private key, ensure you are");
        System.out.println("running this in a secure environment! You can run this tool offline and copy");
        System.out.println("the resulting artifacts to submit on Hemi.\n");
        System.out.println("This tool will NOT send any on-chain transactions - only generate data for you");
        System.out.println("to submit to the VBKRegistry contract on Hemi.\n");
        System.out.println("--------------------------------------------------------------------------------\n");

        try (Scanner scan = new Scanner(System.in)) {

        // Read private key securely (without echo) if console is available
        String fullKey;
        Console console = System.console();
        if (console != null) {
            // Interactive terminal - use secure input (no echo)
            System.out.print("Enter a VeriBlock private key (from CLI dumpprivkey command): ");
            char[] keyChars = console.readPassword();
            if (keyChars == null || keyChars.length == 0) {
                System.out.println("\nERROR: No private key provided.");
                System.out.println("Please run the tool again and enter your VeriBlock private key.");
                return;
            }
            fullKey = new String(keyChars);
            // Clear the char array for security
            Arrays.fill(keyChars, '\0');
            System.out.println("(hidden)");
        } else {
            // Piped input or IDE - fall back to Scanner (for tests/automation)
            System.out.println("Enter a VeriBlock private key (from CLI dumpprivkey command): ");
            fullKey = scan.nextLine();
        }

        // Validate and parse the private key with user-friendly error messages
        fullKey = fullKey.trim();
        if (fullKey.isEmpty()) {
            System.out.println("\nERROR: No private key provided.");
            System.out.println("Please run the tool again and enter your VeriBlock private key.");
            return;
        }

        // Remove 0x prefix if present
        if (fullKey.startsWith("0x") || fullKey.startsWith("0X")) {
            fullKey = fullKey.substring(2);
        }

        // Validate hex format
        byte[] fullBytes;
        try {
            fullBytes = hexToBytes(fullKey);
        } catch (IllegalArgumentException e) {
            System.out.println("\nERROR: Invalid private key format.");
            if (e.getMessage().contains("Odd-length")) {
                System.out.println("The key has an odd number of characters. Hex strings must have even length.");
            } else if (e.getMessage().contains("Non-hex")) {
                System.out.println("The key contains invalid characters. Only hex characters (0-9, a-f, A-F) are allowed.");
            } else {
                System.out.println("Details: " + e.getMessage());
            }
            System.out.println("\nExpected format: The hex output from 'dumpprivkey' command in VeriBlock CLI.");
            return;
        }

        if (fullBytes.length < 32) {
            System.out.println("\nERROR: Private key is too short (" + fullBytes.length + " bytes).");
            System.out.println("A valid VeriBlock private key should be at least 32 bytes.");
            System.out.println("\nMake sure you're using the full output from 'dumpprivkey' command.");
            return;
        }

        // 2) Your original layout: first byte = length, followed by PKCS#8 bytes
        byte[] pkcs8;
        int declaredLen = (fullBytes.length > 0) ? (fullBytes[0] & 0xFF) : 0;
        if (declaredLen > 0 && fullBytes.length >= 1 + declaredLen) {
            pkcs8 = Arrays.copyOfRange(fullBytes, 1, 1 + declaredLen);
        } else {
            // Fallback: assume the whole input is the PKCS#8 DER
            pkcs8 = fullBytes;
        }

        // 3) Parse PKCS#8 EC private key
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        PrivateKey priv;
        try {
            priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            System.out.println("\nERROR: Could not parse private key.");
            System.out.println("The key does not appear to be a valid VeriBlock/PKCS#8 format.");
            System.out.println("\nPossible causes:");
            System.out.println("  - The key was copied incorrectly or is truncated");
            System.out.println("  - This is not a VeriBlock private key");
            System.out.println("  - The key format is corrupted");
            System.out.println("\nPlease verify you're using the exact output from 'dumpprivkey <address>'");
            return;
        }

        if (!(priv instanceof ECPrivateKey)) {
            System.out.println("\nERROR: The key is not an EC (elliptic curve) private key.");
            System.out.println("VeriBlock uses secp256k1 EC keys. This key appears to be a different type.");
            return;
        }
        ECPrivateKey ecPriv = (ECPrivateKey) priv;
        BigInteger s = ecPriv.getS(); // private scalar

        // 3a) Ensure scalar is in secp256k1 range
        BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        if (s.signum() <= 0 || s.compareTo(N) >= 0) {
            System.out.println("\nERROR: Private key value is out of valid range for secp256k1 curve.");
            System.out.println("This may indicate a corrupted or invalid key.");
            return;
        }

        // 4) secp256k1 domain params
        ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        if (bcSpec == null) {
            System.out.println("\nERROR: Internal error - secp256k1 curve parameters not found.");
            System.out.println("This is a bug in the application. Please report this issue.");
            return;
        }

        // 5) Compute public point Q = s * G
        ECPoint Q = bcSpec.getG().multiply(s).normalize();

        // 6) Build a JCA PublicKey (X.509-encoded) – not required for EVM address, but handy to have
        PublicKey pub = kf.generatePublic(new ECPublicKeySpec(Q, bcSpec));
        byte[] x509 = pub.getEncoded();

        MessageDigest md2 = MessageDigest.getInstance("SHA-256");
        md2.update(x509);
        byte[] hash = md2.digest();
        String addr = "V" + Base58.encode(hash).substring(0, 24);
        addr = addr + calculateVBKChecksum(addr);
        System.out.println("VBK Address: " + addr);

        // Display balance from ledger and check if user wants to proceed with zero balance
        boolean hasBalance = displayBalance(addr);
        if (!hasBalance) {
            System.out.println("This VBK address is NOT ELIGIBLE for any reward allocation.");
            System.out.println("You may still register this address, but you will not receive any rewards.\n");
            System.out.print("Do you want to continue anyway? (y/n): ");
            String continueChoice = scan.nextLine().trim().toLowerCase();
            while (!continueChoice.equals("y") && !continueChoice.equals("yes") &&
                   !continueChoice.equals("n") && !continueChoice.equals("no")) {
                System.out.print("Please enter 'y' or 'n': ");
                continueChoice = scan.nextLine().trim().toLowerCase();
            }
            if (continueChoice.equals("n") || continueChoice.equals("no")) {
                System.out.println("\nExiting. No registration will be performed.");
                return;
            }
            System.out.println("\nProceeding with registration (note: no rewards will be allocated)...\n");
        }

        // 7) EVM PRIVATE KEY (32-byte big-endian)
        // Note: Private key is only displayed later if user chooses the derived address option
        byte[] evmPriv = toFixedLengthUnsigned(s, 32);
        String evmPrivHex = "0x" + bytesToHex(evmPriv);

        // 8) EVM ADDRESS from Q (uncompressed pubkey)
        byte[] uncompressed = Q.getEncoded(false);                 // 0x04 || X || Y
        byte[] xy = Arrays.copyOfRange(uncompressed, 1, uncompressed.length); // drop 0x04

        // Extract X and Y coordinates
        byte[] pubKeyX = Arrays.copyOfRange(xy, 0, 32);
        byte[] pubKeyY = Arrays.copyOfRange(xy, 32, 64);

        MessageDigest keccak = getKeccak256();
        byte[] evmAddrHash = keccak.digest(xy);
        byte[] evmAddr = Arrays.copyOfRange(evmAddrHash, 12, 32);  // last 20 bytes
        String checksum = toChecksumAddress(evmAddr);

        // 9) Sanity check: recompute address directly from evmPriv
        ECPoint Q2 = bcSpec.getG().multiply(new BigInteger(1, evmPriv)).normalize();
        byte[] uncompressed2 = Q2.getEncoded(false);
        byte[] xy2 = Arrays.copyOfRange(uncompressed2, 1, uncompressed2.length);
        byte[] evmAddrHash2 = getKeccak256().digest(xy2);
        byte[] evmAddr2 = Arrays.copyOfRange(evmAddrHash2, 12, 32);
        String checksum2 = toChecksumAddress(evmAddr2);
        if (!checksum.equals(checksum2)) {
            throw new IllegalStateException("Address mismatch (from Q vs from evmPriv) – check inputs and curve!");
        }

        System.out.println("Equivalent EVM Address: " + checksum);

        System.out.println("\n=== Select Reward Address ===");
        System.out.println("Where EVM address would you like to use for your rewards?\n");
        System.out.println("  (1) Use derived EVM address: " + checksum);
        System.out.println("  (2) Enter a different EVM address\n");
        System.out.print("Select option (1 or 2): ");
        String selection = scan.nextLine();

        while (!selection.equals("1") && !selection.equals("2")) {
            System.out.print("Invalid input. Please enter 1 or 2: ");
            selection = scan.nextLine();
        }

        String selectedRewardAddress = checksum;
        if (selection.equals("1")) {
            System.out.println("\nUsing derived EVM address: " + checksum);
        } else if (selection.equals("2")) {
            System.out.print("\nEnter the EVM address to receive your rewards: ");
            selectedRewardAddress = scan.nextLine().trim();

            boolean addressAccepted = false;
            while (!addressAccepted) {
                // First check basic format
                while (!isValidEvmAddress(selectedRewardAddress)) {
                    System.out.println("Invalid EVM address. Address must be 42 characters starting with '0x' followed by 40 hex characters.");
                    System.out.print("Please enter a valid EVM address: ");
                    selectedRewardAddress = scan.nextLine().trim();
                }

                // Check for zero address
                while (isZeroAddress(selectedRewardAddress)) {
                    System.out.println("ERROR: The zero address (0x0000...0000) is not allowed as a reward address.");
                    System.out.println("Rewards sent to the zero address would be permanently lost.");
                    System.out.print("Please enter a valid EVM address: ");
                    selectedRewardAddress = scan.nextLine().trim();
                    // Re-check basic format after new input
                    while (!isValidEvmAddress(selectedRewardAddress)) {
                        System.out.println("Invalid EVM address. Address must be 42 characters starting with '0x' followed by 40 hex characters.");
                        System.out.print("Please enter a valid EVM address: ");
                        selectedRewardAddress = scan.nextLine().trim();
                    }
                }

                // Now check checksum
                if (!isChecksumValid(selectedRewardAddress)) {
                    String correctChecksum = toChecksumAddressFromString(selectedRewardAddress);
                    System.out.println("\nWARNING: The address you entered has an EVM address with an invalid checksum.");
                    System.out.println("You entered:      " + selectedRewardAddress);
                    System.out.println("Correct checksum: " + correctChecksum);
                    System.out.println("\nThis could indicate a typo. Please verify carefully!");
                    System.out.println("Options:");
                    System.out.println("(1) Use the corrected checksummed address: " + correctChecksum);
                    System.out.println("(2) Re-enter a different address");
                    System.out.print("Select option (1 or 2): ");
                    String checksumChoice = scan.nextLine().trim();

                    while (!checksumChoice.equals("1") && !checksumChoice.equals("2")) {
                        System.out.print("Please enter 1 or 2: ");
                        checksumChoice = scan.nextLine().trim();
                    }

                    if (checksumChoice.equals("1")) {
                        selectedRewardAddress = correctChecksum;
                        addressAccepted = true;
                    } else {
                        System.out.print("Enter the EVM address to receive your rewards: ");
                        selectedRewardAddress = scan.nextLine().trim();
                        // Loop will continue to validate the new input
                    }
                } else {
                    // Ensure we always use the properly checksummed version
                    selectedRewardAddress = toChecksumAddressFromString(selectedRewardAddress);
                    addressAccepted = true;
                }
            }
        }

        System.out.println("\nReward address confirmed: " + selectedRewardAddress);

        // 10) Get EIP-712 domain parameters
        System.out.println("\n=== Contract Configuration ===\n");
        System.out.print("Chain ID [43111 - Hemi]: ");
        String chainIdStr = scan.nextLine().trim();
        long chainId;
        if (chainIdStr.isEmpty()) {
            chainId = 43111;
        } else {
            try {
                chainId = Long.parseLong(chainIdStr);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input, using default: 43111 (Hemi)");
                chainId = 43111;
            }
        }

        String defaultContract = "0xA7402C49B8947901c5F8A7fcd9AacD820bAcdDdB";
        System.out.print("VBKRegistry contract address [" + defaultContract + "]: ");
        String contractAddress = scan.nextLine().trim();
        if (contractAddress.isEmpty()) {
            contractAddress = defaultContract;
        }
        while (!isValidEvmAddress(contractAddress)) {
            System.out.print("Invalid address. Enter valid contract address (0x...): ");
            contractAddress = scan.nextLine().trim();
        }
        contractAddress = toChecksumAddressFromString(contractAddress);
        byte[] contractAddressBytes = hexToBytes(contractAddress.substring(2));

        // 11) Select operation mode
        System.out.println("\n=== Select Operation ===\n");
        System.out.println("  (1) Register - New registration");
        System.out.println("  (2) Update   - Change reward address for existing registration\n");
        System.out.print("Select option [1]: ");
        String modeSelection = scan.nextLine().trim();
        if (modeSelection.isEmpty()) {
            modeSelection = "1";
        }
        while (!modeSelection.equals("1") && !modeSelection.equals("2")) {
            System.out.print("Invalid input. Please enter 1 or 2: ");
            modeSelection = scan.nextLine().trim();
        }
        boolean isRegister = modeSelection.equals("1");
        String operationType = isRegister ? "Register" : "UpdateRewardAddress";

        // 12) Get signature deadline
        System.out.println("\n=== Signature Deadline ===\n");
        System.out.println("Signatures expire after the deadline to prevent replay attacks.");
        System.out.print("Hours until expiration [8]: ");
        String deadlineInput = scan.nextLine().trim();
        long deadlineHours = 8; // Default 8 hours
        if (!deadlineInput.isEmpty()) {
            try {
                deadlineHours = Long.parseLong(deadlineInput);
                if (deadlineHours <= 0) {
                    System.out.println("Invalid value, using default: 8 hours");
                    deadlineHours = 8;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input, using default: 8 hours");
            }
        }
        long currentTimestamp = System.currentTimeMillis() / 1000L;
        long deadline = currentTimestamp + (deadlineHours * 3600);
        System.out.println("Signature valid until: " + java.time.Instant.ofEpochSecond(deadline).toString());

        // 13) Sign registration message for smart contract using EIP-712
        System.out.println("\n=== Review and Sign ===\n");

        // Terms message
        String termsBase = "By continuing with registering your VBK address to an EVM address, you agree to the Terms & Conditions of all Hemi websites and represent and warrant that (i) you are not a citizen of, resident in, or formed or qualified to transact business in, the United States or the Peoples Republic of China, and (ii) neither you nor, to your knowledge, any of your affiliates or direct beneficial owners, (A) appears on any governmental sanctions or similar list, nor are they otherwise a party with which the Hemi is prohibited to deal under the laws of the United States, and (B) is a person identified as a terrorist organization on any other relevant lists maintained by governmental authorities, nor is a senior foreign political figure, or any immediate family member or close associate of a senior foreign political figure. You further represent and warrant that the EVM address you are associating with your VBK address is and will remain solely controlled by you.\n\n";

        System.out.println("TERMS AND CONDITIONS:");
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println(termsBase);
        System.out.println("--------------------------------------------------------------------------------");
        System.out.println("\nSIGNATURE DETAILS:");
        System.out.println("  Operation:      " + operationType);
        System.out.println("  VBK Address:    " + addr);
        System.out.println("  Reward Address: " + selectedRewardAddress);
        System.out.println("  Chain ID:       " + chainId);
        System.out.println("  Contract:       " + contractAddress);
        System.out.println("  Expires:        " + java.time.Instant.ofEpochSecond(deadline).toString());
        System.out.println("\nPress ENTER to agree to the terms and sign with your VeriBlock key...");
        scan.nextLine();

        // EIP-712 type hashes (include deadline)
        byte[] domainTypeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)".getBytes(StandardCharsets.UTF_8));
        byte[] registerTypeHash = keccak256("Register(bytes32 termsHash,string vbkAddress,address rewardAddress,uint256 deadline)".getBytes(StandardCharsets.UTF_8));
        byte[] updateTypeHash = keccak256("UpdateRewardAddress(bytes32 termsHash,string vbkAddress,address rewardAddress,uint256 deadline)".getBytes(StandardCharsets.UTF_8));
        byte[] termsHash = keccak256(termsBase.getBytes(StandardCharsets.UTF_8));

        // Compute domain separator
        byte[] nameHash = keccak256("VBKRegistry".getBytes(StandardCharsets.UTF_8));
        byte[] versionHash = keccak256("1".getBytes(StandardCharsets.UTF_8));
        byte[] chainIdBytes = toFixedLengthUnsigned(BigInteger.valueOf(chainId), 32);
        byte[] contractAddrPadded = new byte[32];
        System.arraycopy(contractAddressBytes, 0, contractAddrPadded, 12, 20);

        ByteArrayOutputStream domainData = new ByteArrayOutputStream();
        domainData.write(domainTypeHash);
        domainData.write(nameHash);
        domainData.write(versionHash);
        domainData.write(chainIdBytes);
        domainData.write(contractAddrPadded);
        byte[] domainSeparator = keccak256(domainData.toByteArray());

        // Compute struct hash (includes deadline)
        byte[] typeHash = isRegister ? registerTypeHash : updateTypeHash;
        byte[] vbkAddressHash = keccak256(addr.getBytes(StandardCharsets.UTF_8));
        byte[] rewardAddressBytes = hexToBytes(selectedRewardAddress.substring(2));
        byte[] rewardAddrPadded = new byte[32];
        System.arraycopy(rewardAddressBytes, 0, rewardAddrPadded, 12, 20);
        byte[] deadlineBytes = toFixedLengthUnsigned(BigInteger.valueOf(deadline), 32);

        ByteArrayOutputStream structData = new ByteArrayOutputStream();
        structData.write(typeHash);
        structData.write(termsHash);
        structData.write(vbkAddressHash);
        structData.write(rewardAddrPadded);
        structData.write(deadlineBytes);
        byte[] structHash = keccak256(structData.toByteArray());

        // Compute EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
        ByteArrayOutputStream digestData = new ByteArrayOutputStream();
        digestData.write(0x19);
        digestData.write(0x01);
        digestData.write(domainSeparator);
        digestData.write(structHash);
        byte[] messageHash = keccak256(digestData.toByteArray());

        System.out.println("\nSigning...");

        // Sign using ECDSA with deterministic k (RFC 6979)
        ECDomainParameters domainParams = new ECDomainParameters(
            bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN(), bcSpec.getH()
        );
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
            new BigInteger(1, evmPriv), domainParams
        );

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new org.bouncycastle.crypto.digests.SHA256Digest()));
        signer.init(true, privKeyParams);
        BigInteger[] signature = signer.generateSignature(messageHash);

        BigInteger sigR = signature[0];
        BigInteger sigS = signature[1];

        // Ensure s is in the lower half of the curve order (EIP-2)
        BigInteger halfN = N.shiftRight(1);
        if (sigS.compareTo(halfN) > 0) {
            sigS = N.subtract(sigS);
        }

        // Determine recovery id (v = 27 or 28)
        int recId = -1;
        for (int i = 0; i < 2; i++) {
            ECPoint recovered = recoverPublicKey(messageHash, sigR, sigS, i, bcSpec);
            if (recovered != null && recovered.equals(Q)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new IllegalStateException("Could not determine recovery id");
        }
        int v = 27 + recId;

        byte[] rBytes = toFixedLengthUnsigned(sigR, 32);
        byte[] sBytes = toFixedLengthUnsigned(sigS, 32);

        System.out.println("\n================================================================================");
        System.out.println("                         REGISTRATION PARAMETERS");
        System.out.println("================================================================================\n");
        System.out.println("VBK Address: " + addr + "\n");
        System.out.println("Call the \"" + (isRegister ? "register" : "updateRewardAddress") + "\" function with these parameters:\n");
        System.out.println("  pubKeyX:          0x" + bytesToHex(pubKeyX));
        System.out.println("  pubKeyY:          0x" + bytesToHex(pubKeyY));
        System.out.println("  v:                " + v);
        System.out.println("  r:                0x" + bytesToHex(rBytes));
        System.out.println("  s:                0x" + bytesToHex(sBytes));
        System.out.println("  rewardEVMAddress: " + selectedRewardAddress);
        System.out.println("  deadline:         " + deadline);

        System.out.println("\n--------------------------------------------------------------------------------");
        if (selectedRewardAddress.equalsIgnoreCase(checksum)) {
            System.out.println("IMPORTANT: Rewards will be sent to your derived EVM address.");
            System.out.println("To access your rewards, import this private key into your EVM wallet:\n");
            System.out.println("  " + evmPrivHex);
        } else {
            System.out.println("WARNING: Rewards will be sent to a CUSTOM address (not derived from VBK key).");
            System.out.println("Ensure you control the private key for: " + selectedRewardAddress);
            System.out.println("If you do not control this address, YOUR REWARDS WILL BE LOST!");
        }
        System.out.println("--------------------------------------------------------------------------------");

        System.out.println("\nNEXT STEPS:");
        System.out.println("  1. Go to the VBKRegistry contract on Hemi");
        System.out.println("  2. Call \"" + (isRegister ? "register" : "updateRewardAddress") + "\" with the parameters above");
        System.out.println("  3. Submit before: " + java.time.Instant.ofEpochSecond(deadline).toString());
        System.out.println("\n  Signature expires at the deadline - you'll need to sign again if it passes.");

        // 14) Optionally output packed data for single-parameter contract call
        System.out.println("\n=== Optional: Packed Data ===\n");
        System.out.println("You can also call \"" + (isRegister ? "registerPacked" : "updateRewardAddressPacked") + "\" with a single");
        System.out.println("hex string instead of multiple parameters.\n");
        System.out.print("Generate packed data? (y/n) [n]: ");
        String packedChoice = scan.nextLine().trim().toLowerCase();

        if (packedChoice.equals("y") || packedChoice.equals("yes")) {
            // Build ABI-encoded packed data:
            // abi.encode(pubKeyX, pubKeyY, v, r, s, rewardEVMAddress, deadline)
            // Each field is 32 bytes (v and address are padded)
            ByteArrayOutputStream packedData = new ByteArrayOutputStream();

            // pubKeyX (32 bytes)
            packedData.write(pubKeyX, 0, 32);

            // pubKeyY (32 bytes)
            packedData.write(pubKeyY, 0, 32);

            // v (uint8 padded to 32 bytes)
            byte[] vPadded = new byte[32];
            vPadded[31] = (byte) v;
            packedData.write(vPadded, 0, 32);

            // r (32 bytes)
            packedData.write(rBytes, 0, 32);

            // s (32 bytes)
            packedData.write(sBytes, 0, 32);

            // rewardEVMAddress (address padded to 32 bytes - left padded with zeros)
            packedData.write(rewardAddrPadded, 0, 32);

            // deadline (uint256 - 32 bytes)
            packedData.write(deadlineBytes, 0, 32);

            byte[] packed = packedData.toByteArray();

            System.out.println("\nPacked data (" + packed.length + " bytes):\n");
            System.out.println("0x" + bytesToHex(packed));
            System.out.println("\nUse this as the 'data' parameter for " + (isRegister ? "registerPacked" : "updateRewardAddressPacked") + "()");
        }

        System.out.println("\n================================================================================");
        System.out.println("                              COMPLETE");
        System.out.println("================================================================================\n");
        } // end try-with-resources for Scanner
    }

    private static byte[] keccak256(byte[] input) {
        KeccakDigest digest = new KeccakDigest(256);
        digest.update(input, 0, input.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    private static ECPoint recoverPublicKey(byte[] messageHash, BigInteger r, BigInteger s, int recId, ECParameterSpec spec) {
        BigInteger n = spec.getN();
        BigInteger e = new BigInteger(1, messageHash);

        // Calculate the curve point R
        BigInteger x = r;
        if (recId >= 2) {
            x = x.add(n);
        }

        // Check if x is valid
        if (x.compareTo(spec.getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }

        // Decompress the point
        ECPoint R;
        try {
            // Compressed point format: 02 or 03 prefix + x coordinate
            byte[] compressedPoint = new byte[33];
            compressedPoint[0] = (byte) (0x02 + (recId & 1));
            byte[] xBytes = toFixedLengthUnsigned(x, 32);
            System.arraycopy(xBytes, 0, compressedPoint, 1, 32);
            R = spec.getCurve().decodePoint(compressedPoint);
        } catch (Exception ex) {
            return null;
        }

        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger rInv = r.modInverse(n);
        BigInteger eNeg = e.negate().mod(n);

        ECPoint sR = R.multiply(s);
        ECPoint eG = spec.getG().multiply(eNeg);
        ECPoint Q = sR.add(eG).multiply(rInv).normalize();

        return Q;
    }

    private static MessageDigest getKeccak256() {
        try {
            // works if BC provider registered
            return MessageDigest.getInstance("KECCAK-256");
        } catch (NoSuchAlgorithmException e) {
            // direct BC implementation fallback
            return new Keccak.Digest256();
        }
    }

    private static byte[] toFixedLengthUnsigned(BigInteger x, int len) {
        byte[] tmp = x.toByteArray(); // big-endian, may have leading 0x00 sign byte
        int start = (tmp.length > 1 && tmp[0] == 0x00) ? 1 : 0;
        int bytes = tmp.length - start;

        byte[] out = new byte[len];
        if (bytes >= len) {
            System.arraycopy(tmp, start + bytes - len, out, 0, len);     // truncate left
        } else {
            System.arraycopy(tmp, start, out, len - bytes, bytes);       // left-pad zeros
        }
        return out;
    }

    private static String toChecksumAddress(byte[] addr20) {
        String hex = bytesToHex(addr20); // lower-case hex, no 0x
        byte[] hh = getKeccak256().digest(hex.getBytes(StandardCharsets.US_ASCII));
        String hhHex = bytesToHex(hh);

        StringBuilder sb = new StringBuilder(42);
        sb.append("0x");
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (c >= 'a' && c <= 'f') {
                int nibble = Character.digit(hhHex.charAt(i), 16);
                sb.append(nibble >= 8 ? Character.toUpperCase(c) : c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean isValidEvmAddress(String address) {
        if (address == null || address.length() != 42) {
            return false;
        }
        if (!address.startsWith("0x") && !address.startsWith("0X")) {
            return false;
        }
        String hex = address.substring(2);
        for (char c : hex.toCharArray()) {
            if (Character.digit(c, 16) == -1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if an EVM address is the zero address (0x0000...0000).
     */
    private static boolean isZeroAddress(String address) {
        if (!isValidEvmAddress(address)) {
            return false;
        }
        String hex = address.substring(2).toLowerCase();
        return hex.equals("0000000000000000000000000000000000000000");
    }

    /**
     * Checks if an EVM address has a valid  checksum.
     */
    private static boolean isChecksumValid(String address) {
        if (!isValidEvmAddress(address)) {
            return false;
        }
        String hex = address.substring(2);

        // Check if it's all lowercase or all uppercase (not checksummed)
        boolean hasLower = false;
        boolean hasUpper = false;
        for (char c : hex.toCharArray()) {
            if (c >= 'a' && c <= 'f') hasLower = true;
            if (c >= 'A' && c <= 'F') hasUpper = true;
        }

        // If not mixed case, it's not claiming to be checksummed, invalid
        if (!hasLower || !hasUpper) {
            return false;
        }

        // It's mixed case, so verify the checksum
        String lowerHex = hex.toLowerCase();
        byte[] hashBytes = getKeccak256().digest(lowerHex.getBytes(StandardCharsets.US_ASCII));
        String hashHex = bytesToHex(hashBytes);

        for (int i = 0; i < 40; i++) {
            char c = lowerHex.charAt(i);
            if (c >= 'a' && c <= 'f') {
                int nibble = Character.digit(hashHex.charAt(i), 16);
                char expected = nibble >= 8 ? Character.toUpperCase(c) : c;
                if (hex.charAt(i) != expected) {
                    return false;
                }
            }
        }
        return true;
    }


    public static String calculateVBKChecksum(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] hash = md.digest();
            return Base58.encode(hash).substring(0, 5);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Converts an address to its proper EIP-55 checksummed form.
     */
    private static String toChecksumAddressFromString(String address) {
        if (!isValidEvmAddress(address)) {
            return address;
        }
        byte[] addrBytes = hexToBytes(address.substring(2));
        return toChecksumAddress(addrBytes);
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String s) {
        String hex = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        if ((hex.length() & 1) == 1) throw new IllegalArgumentException("Odd-length hex");
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Non-hex character");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * Loads the ledger.json file containing VBK address balances.
     * First tries to load from classpath (for JAR), then from file system.
     */
    private static void loadLedger() {
        // First, try to load from classpath (bundled in JAR)
        InputStream resourceStream = Main.class.getResourceAsStream("/ledger.json");
        if (resourceStream != null) {
            try (InputStreamReader reader = new InputStreamReader(resourceStream, StandardCharsets.UTF_8)) {
                loadLedgerFromReader(reader);
                return;
            } catch (Exception e) {
                System.out.println("[Warning: Could not load ledger.json from JAR: " + e.getMessage() + "]");
            }
        }

        // Fall back to file system search
        String[] searchPaths = {
            "ledger.json",                    // Current directory
            "../ledger.json",                 // Parent directory
            "VBKToEVMConverter/ledger.json",  // From project root
            System.getProperty("user.dir") + "/ledger.json"
        };

        File ledgerFile = null;
        for (String path : searchPaths) {
            File f = new File(path);
            if (f.exists() && f.isFile()) {
                ledgerFile = f;
                break;
            }
        }

        if (ledgerFile == null) {
            System.out.println("[Note: ledger.json not found - balance lookup unavailable]");
            return;
        }

        try (FileReader reader = new FileReader(ledgerFile)) {
            loadLedgerFromReader(reader);
        } catch (Exception e) {
            System.out.println("[Warning: Could not load ledger.json: " + e.getMessage() + "]");
        }
    }

    /**
     * Parses ledger data from a Reader.
     */
    private static void loadLedgerFromReader(java.io.Reader reader) {
        Gson gson = new Gson();
        JsonObject root = gson.fromJson(reader, JsonObject.class);

        ledgerBlockHeight = root.get("block").getAsLong();
        int addressCount = root.get("address_count").getAsInt();
        JsonArray addresses = root.getAsJsonArray("addresses");

        for (JsonElement elem : addresses) {
            JsonObject entry = elem.getAsJsonObject();
            String address = entry.get("address").getAsString();
            BigInteger amount = entry.get("amount").getAsBigInteger();
            ledgerBalances.put(address, amount);
        }

        System.out.println("[Loaded ledger: " + ledgerBalances.size() + " addresses from block " + ledgerBlockHeight + "]\n");
    }

    /**
     * Displays the balance for a VBK address from the loaded ledger.
     * @return true if the address has a positive balance, false otherwise
     */
    private static boolean displayBalance(String vbkAddress) {
        if (ledgerBalances.isEmpty()) {
            // Ledger not loaded - can't determine balance
            return true; // Allow to proceed without warning
        }

        BigInteger balanceAtomic = ledgerBalances.get(vbkAddress);
        if (balanceAtomic == null || balanceAtomic.compareTo(BigInteger.ZERO) == 0) {
            System.out.println("\n**********************************************************************");
            System.out.println("*  WARNING: This VBK address has NO BALANCE in the ledger snapshot  *");
            System.out.println("**********************************************************************\n");
            return false;
        }

        // Convert atomic units to VBK (8 decimal places)
        BigDecimal balance = new BigDecimal(balanceAtomic).divide(VBK_DIVISOR, 8, RoundingMode.DOWN);

        // Format with thousands separators
        NumberFormat formatter = NumberFormat.getNumberInstance(Locale.US);
        formatter.setMinimumFractionDigits(8);
        formatter.setMaximumFractionDigits(8);
        String formattedBalance = formatter.format(balance);

        System.out.println("\n=== VBK Balance (snapshot at block " + ledgerBlockHeight + ") ===");
        System.out.println("Balance: " + formattedBalance + " VBK\n");
        return true;
    }
}