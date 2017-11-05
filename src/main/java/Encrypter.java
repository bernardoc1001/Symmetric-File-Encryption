package main.java;

import java.io.*;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Encrypter {

    static String hexStringN = "c406136c 12640a66 5900a9df 4df63a84 fc855927 b729a3a1 06fb3f37 9e8e4190" +
            "ebba442f 67b93402 e535b18a 5777e649 0e67dbee 954bb021 75e43b64 81e7563d" +
            "3f9ff338 f07950d1 553ee6c3 43d3f814 8f71b4d2 df8da7ef b39f846a c07c8652" +
            "01fbb35e a4d71dc5 f858d9d4 1aaa856d 50dc2d27 32582f80 e7d38c32 aba87ba9";

    static final BigInteger N = new BigInteger(hexStringN.replaceAll("\\s+",""), 16);

    static final BigInteger E = new BigInteger("65537");

    // Right to left variant of calculating modular exponentiation
    private static BigInteger performRSA(BigInteger base, BigInteger exponent, BigInteger mod){
        BigInteger y = new BigInteger("1");
        for(int i = 0; i < exponent.bitLength(); i++){
            if (exponent.testBit(i)) {
                y = y.multiply(base);
                y = y.mod(mod);
            }
            base = base.multiply(base);
            base = base.mod(mod);
        }
        return y;
    }

    static final int BYTE_BLOCK_SIZE = 16; //16 bytes == 128 bits

    private static byte[] applyPadding(byte[] inputMessage){
        int remainder = inputMessage.length % BYTE_BLOCK_SIZE;
        int paddedArrayLength;

        //Determine how long the new padded array will have to be
        if(remainder == 0){
            paddedArrayLength = inputMessage.length + BYTE_BLOCK_SIZE;
        }
        else{
            paddedArrayLength = inputMessage.length + BYTE_BLOCK_SIZE - remainder;
        }

        byte[] paddedArray = new byte[paddedArrayLength];
        System.arraycopy(inputMessage, 0, paddedArray, 0, inputMessage.length);

        //Add padding
        paddedArray[inputMessage.length] = (byte) 128; //First padded byte begins with 1 and rest 0's
        //Now loop to make the rest of the padded bytes all 0's
        for(int j = inputMessage.length + 1; j < paddedArray.length; j++){
            paddedArray[j] = (byte) 0;
        }

        return paddedArray;
    }

    private static void writeByteArrayToFile(byte[] fileData, String outputPath) throws IOException{
        FileOutputStream out = new FileOutputStream(outputPath);
        System.out.println("Writing to file: " + outputPath);
        out.write(fileData);
        out.close();
    }

    private static void writeAssignmentHandInToFile(String outputPath,
                                                    byte[] salt,
                                                    byte[] iv,
                                                    byte[] unencryptedAESKey,
                                                    BigInteger passwordRSA,
                                                    byte[] encryptedFileAES) throws IOException {
        PrintWriter printwriter = new PrintWriter(outputPath, "UTF-8");
        System.out.println("Writing assignment hand-in details to: " + outputPath);
        printwriter.println("Salt: " + DatatypeConverter.printHexBinary(salt));
        printwriter.println("\nIV: " + DatatypeConverter.printHexBinary(iv));
        printwriter.println("\nUnencrypted AES key: " + DatatypeConverter.printHexBinary(unencryptedAESKey));
        printwriter.println("\nRSA Encrypted Password: " + passwordRSA.toString(16));
        printwriter.println("\nEncrypted File: " + DatatypeConverter.printHexBinary(encryptedFileAES));
        printwriter.close();
    }

    public static void main(String [] args) {
        Scanner scan = new Scanner(System.in, "UTF-8");
        System.out.println("Please enter a password: ");
        String passwordString = scan.next();
        try {
            byte[] p = passwordString.getBytes("UTF-8"); //p = the password in a utf-8 byte array

            //========================= generate the 128 bit salt ===============
            SecureRandom srng = new SecureRandom();
            byte[] saltByteArray = new byte[16];
            srng.nextBytes(saltByteArray);

            //=============== concatenate the byte arrays p and s into ps =======
            byte[] ps = new byte[p.length + saltByteArray.length];
            int index = 0;
            for(int j = 0; j < p.length; j++){
                ps[j] = p[j];
                index++;
            }
            for(int j = 0; j < saltByteArray.length; j++){
                ps[index] = saltByteArray[j];
                index++;
            }


            //=========== hash ps 200 times with SHA-256 to make AES-256 key k ============
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] keyByteArray = digest.digest(ps);      //hashed once
                for(int j = 0; j < 199; j++){                 //hash 199 more times
                    keyByteArray = digest.digest(keyByteArray);
                }

                //generate IV (i), which is a random 128 bit value
                byte[] ivByteArray = new byte[16];
                srng.nextBytes(ivByteArray);

                //======================== read in file and encrypt it ==================
                //Read in file into byte array
                System.out.println("Enter the filepath for the file you wish to encrypt: ");
                Path filePath = Paths.get(scan.next());
                try {
                    byte[] fileData = Files.readAllBytes(filePath);

                    //Perform Padding
                    byte[] paddedFileData = applyPadding(fileData);

                    //convert key and iv byte arrays to their respective objects
                    SecretKeySpec k = new SecretKeySpec(keyByteArray, "AES");
                    IvParameterSpec i = new IvParameterSpec(ivByteArray);

                    //Create Cipher
                    try {
                        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                        cipher.init(Cipher.ENCRYPT_MODE, k, i);

                        //Perform encryption
                        byte[] encryptedFileData = cipher.doFinal(paddedFileData);

                        //Write encrypted data to file
                        String outputPath = filePath.getParent() +
                                File.separator +
                                "ENCRYPTED-" +
                                filePath.getFileName();
                        writeByteArrayToFile(encryptedFileData, outputPath);

                        //Debug Byte Length Print Out
                        System.out.println("Input file data length: " + fileData.length + " bytes");
                        System.out.println("Padded file data length: " + paddedFileData.length + " bytes");
                        System.out.println("Encrypted file data length: " + encryptedFileData.length + " bytes");




                        //====================== Perform RSA on password =========================================
                        //convert password (p) byte array to BigInteger
                        BigInteger passwordBigInt = new BigInteger(p);

                        //perform RSA encryption
                        BigInteger rsaEncryptedPassword = performRSA(passwordBigInt, E, N); //using constant E and N from the assignment description

                        //============= Write all assignment hand in info to a file ==========================
                        String outputFilePath = filePath.toString() + "-assignment-output";

                        writeAssignmentHandInToFile(outputFilePath, saltByteArray, ivByteArray,keyByteArray, rsaEncryptedPassword, encryptedFileData);



                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                        System.exit(-1);
                    } catch (InvalidKeyException e){
                        e.printStackTrace();
                        System.exit(-1);
                    } catch (InvalidAlgorithmParameterException e){
                        e.printStackTrace();
                        System.exit(-1);
                    } catch (IllegalBlockSizeException e){
                        e.printStackTrace();
                        System.exit(-1);
                    } catch (BadPaddingException e){
                        e.printStackTrace();
                        System.exit(-1);
                    }
                }
                catch(IOException e){
                    e.printStackTrace();
                    System.exit(-1);
                }
            }
            catch (NoSuchAlgorithmException e){
                e.printStackTrace();
                System.exit(-1);
            }
        }
        catch (UnsupportedEncodingException e){
            e.printStackTrace();
            System.exit(-1);
        }
    }
}

