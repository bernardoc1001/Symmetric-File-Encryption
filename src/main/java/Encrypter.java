package main.java;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encrypter {

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

    private static void writeByteArrayToFile(byte[] fileData, String outputPath) throws IOException {
        FileOutputStream out = new FileOutputStream(outputPath);
        System.out.println("Writing encrypted file to: " + outputPath);
        out.write(fileData);
        out.close();
    }


    public static void main(String [] args) {
        Scanner scan = new Scanner(System.in, "UTF-8");
        System.out.println("Please enter a password: ");
        String passwordString = scan.next();
        try {
            byte[] p = passwordString.getBytes("UTF-8"); //p = the password in a utf-8 byte array
            //print out byte array, TODO remove before final submission
            System.out.println("printing p");
            for (int j = 0; j < p.length; j++){
                System.out.println(p[j]);
            }

            //========================= generate the 128 bit salt ====================================================
            SecureRandom srng = new SecureRandom();
            byte[] s = new byte[16];
            srng.nextBytes(s);
            //print out byte array, TODO remove before final submission
            System.out.println("printing s");
            for(int j = 0; j < s.length; j++){
                System.out.println(s[j]);
            }

            //=============== concatenate the byte arrays p and s into ps ========================================
            byte[] ps = new byte[p.length + s.length];
            int index = 0;
            for(int j = 0; j < p.length; j++){
                ps[j] = p[j];
                index++;
            }
            for(int j = 0; j < s.length; j++){
                ps[index] = s[j];
                index++;
            }

            System.out.println("print out both concatenated:");
            for(int j = 0; j < ps.length; j++){
                System.out.println(ps[j]);
            }

            //=========== hash ps 200 times with SHA-256 to make AES-256 key k ====================================
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] keyByteArray = digest.digest(ps); //hashed once
                for(int j = 1; j < 200; j++){
                    keyByteArray = digest.digest(keyByteArray);
                }

                //generate IV (i), which is a random 128 bit value
                byte[] ivByteArray = new byte[16];
                srng.nextBytes(ivByteArray);

                //======================== read in file and encrypt it ================================================
                    //Read in file into byte array
                System.out.println("Enter the filepath for the file you wish to encrypt: ");
                //TODO sanitise path
                Path filePath = Paths.get(scan.next());
                try {
                    byte[] fileData = Files.readAllBytes(filePath);


                    //Perform Padding
                    byte[] paddedFileData = applyPadding(fileData);
                    System.out.println("Input file data length: " + fileData.length);
                    System.out.println("Padded file data length: " + paddedFileData.length);

                    //convert key and iv byte arrays to their respective objects
                    SecretKeySpec k = new SecretKeySpec(keyByteArray, "AES");
                    IvParameterSpec i = new IvParameterSpec(ivByteArray);

                    //Create Cipher
                    try {
                        System.out.println("Max AES key size: " + Cipher.getMaxAllowedKeyLength("AES"));
                        System.out.println("My key size: " + k.getEncoded().length * 8);
                        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                        cipher.init(Cipher.ENCRYPT_MODE, k, i);
                        System.out.println("Block size: " + cipher.getBlockSize() * 8);

                        //Perform encryption
                        byte[] encryptedFileData = cipher.doFinal(paddedFileData);

                        //write encrypted file
                        System.out.println("File name: " + filePath.getFileName().toString());
                        String outputPath = filePath.getParent()
                                + File.separator
                                + "ENCRYPTED-"
                                +  filePath.getFileName();
                        writeByteArrayToFile(encryptedFileData, outputPath);




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

