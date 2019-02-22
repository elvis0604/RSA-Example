import java.security.KeyFactory;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;
public class AliceProgramRSA
{
	static PublicKey publicKey;
	static PrivateKey privateKey;
	final static int numRun = 100;
	
	public static KeyPair generateKeyPair() throws Exception 
	{
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(2048, new SecureRandom());
	    KeyPair pair = generator.generateKeyPair();

	    return pair;
	}
	
	public static String encrypt(String plainText, PublicKey publicKey) throws Exception 
	{
	    Cipher encryptCipher = Cipher.getInstance("RSA");
	    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

	    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
	    System.out.println("Encryption Success!");
	    return Base64.getEncoder().encodeToString(cipherText);
	}
	
	public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception 
	{
	    byte[] bytes = Base64.getDecoder().decode(cipherText);

	    Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
	    System.out.println("Decrypted Success!");//Debugging
	    return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
	}
	
    static String readFile(String path, Charset encoding) throws IOException 
 	{
 		 byte[] encoded = Files.readAllBytes(Paths.get(path));
 		 return new String(encoded, encoding);
 	}
     
	static void writeFile(String filename, String ciphertext)
	{
		 try
		 {
			 File file = new File(filename);
			 FileUtils.writeStringToFile(file, ciphertext, Charset.defaultCharset());
			 System.out.println("File Written Successfully");
		 } catch (IOException e) {
			 e.printStackTrace();
		 }
	}
	 
	private static void printKeyPair(KeyPair keyPair) 
	{
		PublicKey pub = keyPair.getPublic();
		System.out.println("Public Key: " + getHexString(pub.getEncoded()));
 
		PrivateKey priv = keyPair.getPrivate();
		System.out.println("Private Key: " + getHexString(priv.getEncoded()));
	}	
	
	private static void printPublic(PublicKey pub) 
	{
		System.out.println("Public Key: " + getHexString(pub.getEncoded()));
	}	
	
	private static void printPrivate(PrivateKey priv) 
	{
		System.out.println("Private Key: " + getHexString(priv.getEncoded()));
	}	
	
	private static String getHexString(byte[] b) 
	{
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}
	
	public static void save(String path, KeyPair keyPair) throws IOException 
	{
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
 
	public static PublicKey loadPublic(String filename) 
	throws IOException, NoSuchAlgorithmException, InvalidKeySpecException 
	{
		// Read Public Key.
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

	    X509EncodedKeySpec spec =
	      new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}	
	
	public static PrivateKey loadPrivate(String filename) 
	throws IOException, NoSuchAlgorithmException, InvalidKeySpecException 
	{
		 byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
		
		 PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		 KeyFactory kf = KeyFactory.getInstance("RSA");
		 return kf.generatePrivate(spec);
	}
	
	public static boolean checkFile(String filePath)
	{
		File f = new File(filePath);
		return (f.exists() && !f.isDirectory());
	}
	
    public static void runTime(float runtime)
    {
        System.out.println("Run time: " + runtime + " ms");
        System.out.println("Average run time: " + runtime / numRun + " ms");
    }

	public static void main(String[] args) throws Exception 
	{
        if (args.length != 1) 
        {
            System.err.println("Usage: java <string message>");
        } else 
        {
			try
			{
				//Our secret message+
				String originalMessage = args[0];
				String filepath = "C:\\Users\\anhtu\\eclipse-workspace\\RSA-Example\\public.key";
				if(checkFile(filepath))  //check if file exist; return true if exist
				{ 
					//Getting public and private key
					publicKey = loadPublic("public.key");
					privateKey = loadPrivate("private.key");
					System.out.println("Keys loaded");
					
					//Encrypting
					String cipherText = "";					
			    	long startTime = System.currentTimeMillis();
					for(int i = 0; i < numRun; i++)
			    	{	
						cipherText = encrypt(originalMessage, publicKey);
			    	}
			    	long stopTime = System.currentTimeMillis();
			        float elapsedTime = stopTime - startTime;
			        
					//Write into file
					writeFile("ctext.txt", cipherText);
					
					//Calculating runtime
			        runTime(elapsedTime);
				}
				else
					System.out.println("public.key or private.key doesn't exist. Please run BobProgramRSA");
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
        }
	}
}
