package main.java;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Scanner;
import javax.crypto.*;

public class Encrypter {


    public static void main(String [] args) {
        Scanner scan = new Scanner(System.in, "UTF-8");
        System.out.println("Please enter a password: ");
        String passwordString = scan.next();
        try {
            byte[] p = passwordString.getBytes("UTF-8"); //p = the password in a utf-8 byte array
            //print out byte array, TODO remove before final submission
            System.out.println("printing p");
            for (int i = 0; i < p.length; i++){
                System.out.println(p[i]);
            }

            //generate the 128 bit salt
            SecureRandom srng = new SecureRandom();
            byte[] s = new byte[16];
            srng.nextBytes(s);
            //print out byte array, TODO remove before final submission
            System.out.println("printing s");
            for(int j = 0; j < s.length; j++){
                System.out.println(s[j]);
            }

            //concatenate the byte arrays p and s into ps
            byte[] ps = new byte[p.length + s.length];
            int index = 0;
            for(int i = 0; i < p.length; i++){
                ps[i] = p[i];
                index++;
            }
            for(int j = 0; j < s.length; j++){
                ps[index] = s[j];
                index++;
            }

            System.out.println("print out both concatenated:");
            for(int i = 0; i < ps.length; i++){
                System.out.println(ps[i]);
            }

            //hash ps 200 times with SHA-256 to make AES-256 key k
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] k = digest.digest(ps); //hashed once
                for(int i = 1; i < 200; i++){
                    k = digest.digest(k);
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

