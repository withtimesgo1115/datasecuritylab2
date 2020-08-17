package rmidemo.rmiserver;

import java.io.IOException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;

import rmidemo.rmiinterface.Login;
import rmidemo.rmiinterface.Printing;
import rmidemo.rmiinterface.RMIInterface;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import java.util.Map.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.AbstractMap.SimpleEntry;

public class ServerOperation extends UnicastRemoteObject implements RMIInterface{

    private HashMap<String, String> config = new HashMap<String, String>();
    private HashMap<UUID, Entry<String, LocalDateTime>> userSessionMap = new HashMap<UUID, Entry<String, LocalDateTime>>();
    private HashMap<String, String> userPassMap = new HashMap<String, String>();
    private HashMap<String, ArrayList<String>> queue = new HashMap<String, ArrayList<String>>();

    private static final int TIMEOUT = 600; // Timeout in seconds
    private static final long serialVersionUID = 1L;
    private static DiffeHillmanServer diffeHillmanserver;
    private boolean isRunning = false;
   

    protected ServerOperation() throws RemoteException {
        super();
        userPassMap.put("ella", "ali");
        userPassMap.put("", "");
        userPassMap.put("bullying", "embargo");
    }

    private boolean authenticate(UUID session)
    {
        SimpleEntry<String, LocalDateTime> value = (SimpleEntry<String, LocalDateTime>)userSessionMap.get(session);

        return value == null ? false : !value.getValue().isBefore(LocalDateTime.now().minusSeconds(TIMEOUT));
    }

    private String getUsername(UUID session)
    {
        SimpleEntry<String, LocalDateTime> value = (SimpleEntry<String, LocalDateTime>)userSessionMap.get(session);

        return value == null ? "" : value.getKey();
    }

    @Override
    public boolean isLoggedIn(String username)
    {
        System.out.println("isLoggedIn("+username+")");

        for (Entry<UUID, Entry<String, LocalDateTime>> token : userSessionMap.entrySet())
        {
            if (token.getValue().getKey().equals(username))
            {
                return authenticate(token.getKey());
            }
        }

        return false;
    }

    @Override
    public UUID login(Login login) throws NoSuchPaddingException, Exception
    {
    	
       
        
 	   	String username = sendEncryptedData(login.getEncodedParams(),login.getUsername());
 	   	String password = sendEncryptedData(login.getEncodedParams(),login.getPassword());
        String pwToCheck = (String)userPassMap.get(username);

        if (pwToCheck == null || !pwToCheck.equals(password))
        {
            return null;
        }

        UUID session = UUID.randomUUID();
        userSessionMap.put(session, new SimpleEntry<String, LocalDateTime>(username, LocalDateTime.now()));
        System.out.println("login("+username+","+password+")");
        return session;
    }

    @Override
    public String print(byte[] encodedParams,byte [] filename, byte[] printer, UUID session) throws NoSuchPaddingException, Exception{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }
        String file = new String(filename);
        String print = new String(filename);
        System.out.println(getUsername(session) + ": print("+file+","+print+")");

        if (!isRunning)
        {
            return "Service is not running";
        }
        
        ArrayList<String> printerQueue;

        if (!queue.keySet().contains(printer))
        {
            printerQueue = new ArrayList<String>();
            //queue.put(printer, printerQueue);
        }
        else
        {
            printerQueue = queue.get(printer);
        }

        //printerQueue.add(filename);

        return "Printing " + file + " on " + print;
    }

    @Override
    public String queue(String printer, UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": queue()");

        if (!isRunning)
        {
            return "service is not running";
        }

        if (!queue.keySet().contains(printer))
        {
            return "Queue is empty";
        }

        ArrayList<String> printerQueue = queue.get(printer);
        String queueStr = "";
        int c = 0;

        for (Iterator<String> i = printerQueue.iterator(); i.hasNext();)
        {
            c++;
            queueStr += String.format("%d: %s\n", c, i.next());
        }

        return queueStr;
    }

    @Override
    public String topQueue(String printer, int job, UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": topQueue("+job+")");

        if (!isRunning)
        {
            return "service is not running";
        }

        if (!queue.keySet().contains(printer))
        {
            return "Queue is empty";
        }

        ArrayList<String> printerQueue = queue.get(printer);

        if (job > printerQueue.size() || job < 1)
        {
            return "Invalid job index!";
        }

        String targetJob = (String)printerQueue.get(job-1);

        for (int i = job-1; i > 0; i--)
        {
            printerQueue.set(i, printerQueue.get(i-1));
        }

        printerQueue.set(0, targetJob);

        return "Job " + job + " moved to top of queue for " + printer;
    }

    @Override
    public String start(UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": start()");

        if (isRunning)
        {
            return "Already running";
        }

        isRunning = true;
        return "Starting...";
    }

    @Override
    public String stop(UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": stop()");

        if (!isRunning)
        {
            return "Already stopped";
        }

        isRunning = false;
        queue = new HashMap<String, ArrayList<String>>();
        return "Stopping...";
    }

    @Override
    public String restart(UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": restart()");
        
        stop(session);
        start(session);
        return "Restarting...";
    }

    @Override
    public String status(String printer, UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": status()");

        if (!isRunning)
        {
            return "service is not running";
        }

        if (!queue.keySet().contains(printer))
        {
            return "Queue is empty";
        }

        ArrayList<String> printerQueue = queue.get(printer);

        if (printerQueue == null || printerQueue.isEmpty())
        {
            return printer + " is available";
        }
        
        return printer + " is busy (queue length: " + printerQueue.size() + ")";
    }

    @Override
    public String readConfig(String parameter, UUID session) throws RemoteException{
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": readConfig("+parameter+")");

        String confValue = config.get(parameter);

        return confValue == null ? "" : confValue;
    }
    @Override
    public byte[]  DiffeHillmenServer(byte[] alicePubKeyEnc) throws RemoteException, Exception{
		diffeHillmanserver = new DiffeHillmanServer();
    	return diffeHillmanserver.init(alicePubKeyEnc);
    }
    
    public String sendEncryptedData(byte[] encodedParams,byte[] ciphertext) throws Exception, NoSuchPaddingException {
    	diffeHillmanserver.setEncodedParams(encodedParams);
    	diffeHillmanserver.initSymmetricConnection();
        return diffeHillmanserver.doSymmetricEncryption(ciphertext);
	}

    
    @Override
    public String setConfig(String parameter, String value, UUID session){
        if (!authenticate(session))
        {
            return "AUTENTICATION ERROR!!!!!!!!";
        }

        System.out.println(getUsername(session) + ": setConfig("+parameter+","+value+")");

        config.put(parameter, value);

        return "Set parameter " + parameter + " to " + value;
    }


    public static void main(String[] args){

        try {
            //System.setProperty("java.rmi.server.hostname","192.168.168.231");

            //Naming.rebind("//127.0.0.1/MyServer", new ServerOperation()); 
            System.out.println("Server ready");
    		Registry registry = LocateRegistry.createRegistry(5099);
    		registry.rebind("MyServer", new ServerOperation());
        } catch (Exception e) {

            System.out.println("Server exception: " + e.toString());
            e.printStackTrace();

        }

    }
    /* Converts a byte to hex digit and writes to the supplied buffer
    */

   
   public void sendPrintingObject(Printing print) throws NoSuchPaddingException, Exception{	   
	   //System.out.println("printer"+print.getPrinter());
	   //System.out.println("printer"+print.getFilename());
	   sendEncryptedData(print.getEncodedParams(),print.getFilename());
	   sendEncryptedData(print.getEncodedParams(),print.getPrinter());
   }
}
