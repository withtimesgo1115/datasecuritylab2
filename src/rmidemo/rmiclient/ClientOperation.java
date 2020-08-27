package rmidemo.rmiclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import rmidemo.rmiinterface.Login;
import rmidemo.rmiinterface.Printing;
import rmidemo.rmiinterface.RMIInterface;

public class ClientOperation {

	private static BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	private static RMIInterface server;
	private static String username = "";
	private static String password = "";
	private static UUID session;
	private static DiffeHillmanClient diffeHillmen;
	private static UUID login() throws NoSuchPaddingException, Exception
	{
		Login login = new Login();
		System.out.print("Username: ");
		username = br.readLine();
		byte [] encryptedUsername = diffeHillmen.doSymmetricEncryption(username);
		login.setUsername(encryptedUsername);
		System.out.print("Password: ");
		password = br.readLine();
		byte [] encryptedPassword = diffeHillmen.doSymmetricEncryption(password);
		login.setPassword(encryptedPassword);
		login.setEncodedParams(diffeHillmen.getEncodedParams());
		return server.login(login);
	}
	




	private static void refreshAuth() throws NoSuchPaddingException, Exception
	{
		while (!server.isLoggedIn(username))
		{
			session = login();
		}
	}

	private static void execute(int cmd) throws NoSuchPaddingException, Exception
	{
		String filename;
		byte[] Encryptedfilename;
		String printer;
		byte[] encryptedPrinter;
		int job;
		String parameter;
		String value;
		switch (cmd)
		{
			case 1:
				System.out.print("Filename: ");
				filename = br.readLine();
				
			    Encryptedfilename = diffeHillmen.doSymmetricEncryption(filename);
				System.out.print("Printer: ");
				printer = br.readLine();
				encryptedPrinter = diffeHillmen.doSymmetricEncryption(printer);
				refreshAuth();
				Printing print = new Printing(diffeHillmen.getEncodedParams(),Encryptedfilename,encryptedPrinter);
				server.sendPrintingObject(print);
				//System.out.println(server.print(encodedParams,Encryptedfilename, encryptedPrinter, session));
				break;

			case 2:
				System.out.print("Printer: ");
				printer = br.readLine();

				refreshAuth();
				System.out.println(server.queue(printer, session));
				break;

			case 3:
				System.out.print("Printer: ");
				printer = br.readLine();
				System.out.print("Job: ");
				job = Integer.parseInt(br.readLine());

				refreshAuth();
				System.out.println(server.topQueue(printer, job, session));
				break;

			case 4:
				refreshAuth();
				System.out.println(server.start(session));
				break;

			case 5:
				refreshAuth();
				System.out.println(server.stop(session));
				break;

			case 6:
				refreshAuth();
				System.out.println(server.restart(session));
				break;

			case 7:
				System.out.print("Printer: ");
				printer = br.readLine();

				refreshAuth();
				System.out.println(server.status(printer, session));
				break;

			case 8:
				System.out.print("Parameter: ");
				parameter = br.readLine();

				refreshAuth();
				System.out.println(server.readConfig(parameter, session));
				break;

			case 9:
				System.out.print("Parameter: ");
				parameter = br.readLine();
				System.out.print("Value: ");
				value = br.readLine();

				refreshAuth();
				System.out.println(server.setConfig(parameter, value, session));
				break;

			case 0:
				System.out.println("Quitting...");
		}
	}

	public static void main(String[] args) throws MalformedURLException, RemoteException, NotBoundException {
		
		//server = (RMIInterface) Naming.lookup("//localhost/MyServer");
		 server = (RMIInterface)Naming.lookup("rmi://localhost:5099/MyServer");

		try {
			int cmd = -1;
			 diffeHillmen = new DiffeHillmanClient();
			 diffeHillmen.DiffeHillmenInit();
			 byte[] alicePubKeyEnc = diffeHillmen.getAlicePubKeyEnc();
			 byte[] bobPubKeyEnc = server.DiffeHillmenServer(alicePubKeyEnc);
			 diffeHillmen.setBobPubKeyEnc(bobPubKeyEnc);
			 diffeHillmen.generateSharedSecret();
			 diffeHillmen.initSymmetricConnection();
			while (cmd != 0)
			{
				System.out.println();
				System.out.println("1. print");
				System.out.println("2. queue");
				System.out.println("3. topQueue");
				System.out.println("4. start");
				System.out.println("5. stop");
				System.out.println("6. restart");
				System.out.println("7. status");
				System.out.println("8. readConfig");
				System.out.println("9. setConfig");
				System.out.println("0. quit");
				System.out.print(">");
	
				cmd = Integer.parseInt(br.readLine());
				execute(cmd);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
