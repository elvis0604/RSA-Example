import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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

public class BobProgramRSA 
{
	static String decryptedStr;
	final static int numRun = 100;
	public static KeyPair generateKeyPair() throws Exception 
	{
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(2048, new SecureRandom());
	    KeyPair pair = generator.generateKeyPair();

		System.out.println("Generated Key Pair");
	    return pair;
	}
	
	public static String decrypt(String ciphertext, PrivateKey privateKey) throws Exception 
	{
	    byte[] bytes = Base64.getDecoder().decode(ciphertext);

	    Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

	    return new String(decriptCipher.doFinal(bytes), StandardCharsets.UTF_8);
	}
	
    static String readFile(String path, Charset encoding) throws IOException 
 	{
 		 byte[] encoded = Files.readAllBytes(Paths.get(path));
 		 return new String(encoded, encoding);
 	}
     
	static void writeFile(String filename, String context)
	{
	 	try{
	     	PrintWriter outputStream = new PrintWriter(filename);
	     	outputStream.println(context);	
	     	outputStream.close();	//Need to flush content into the file
	     	//System.out.println("Done");	//debug
	 	} catch (FileNotFoundException e){
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
	
	public static void savePublic(String path, KeyPair keyPair) throws IOException 
	{
		PublicKey publicKey = keyPair.getPublic();
 
		// Store Public Key.
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
				publicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/public.key");
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
	}
	
	public static void savePrivate(String path, KeyPair keyPair) throws IOException 
	{
		PrivateKey privateKey = keyPair.getPrivate();
 
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(path + "/private.key");
		fos.write(pkcs8EncodedKeySpec.getEncoded());
		fos.close();
	}
 
	public static PublicKey loadPublic(String filename) 
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException 
	{
		// Read Public Key.
	    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

	    X509EncodedKeySpec spec =
	      new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}	
	
	public static PrivateKey loadPrivate(String filename) 
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException 
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
		try
		{
			//First generate a public/private key pair
			String filepath = "C:\\Users\\anhtu\\eclipse-workspace\\RSA-Example\\public.key";
			if(!checkFile(filepath))  //check if file exist; return true if exist
			{ 
				String path = "C:\\Users\\anhtu\\eclipse-workspace\\RSA-Example";
				KeyPair pair = generateKeyPair();
		 
				//Saving keys
				savePublic(path, pair);
				savePrivate(path, pair);
				System.out.println("Keys Generated and Saved");
			}  else
			{
				System.out.println("Keys existed");
				//Getting private key
				PrivateKey privateKey = loadPrivate("private.key");
				
				//Decrypting
				String cipherText = readFile("ctext.txt", StandardCharsets.UTF_8);
		    	long startTime = System.currentTimeMillis();
		    	for(int i = 0; i < numRun; i++)
		    	{
					decryptedStr = decrypt(cipherText, privateKey);
		    	}
		    	long stopTime = System.currentTimeMillis();
		        float elapsedTime = stopTime - startTime;
		        
				System.out.println(decryptedStr);
				
				//Calculate runtime
		        runTime(elapsedTime);
			}
		} catch (Exception e) 
		{
			e.printStackTrace();
			return;
		}
	}

}
