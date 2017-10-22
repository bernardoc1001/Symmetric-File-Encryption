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
        }
        catch (UnsupportedEncodingException e){
            e.printStackTrace();
            System.exit(-1);
        }
    }
}

