package kerbeross;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.BadPaddingException; 
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class client {

    public static void main(String[] args) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        int AUTH_PORT = 5000;
        int AS_PORT = 5003;
        int TGS_PORT = 5002;
        int V_PORT = 5001;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Converter conv = new Converter();
        Encryptor encryptor = new Encryptor();
        String Kctgs, IDtgs, TS2, lifetime2;
        
        try{
            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipAC = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Cliente
            byte[] encodedSecretC = comunicator.getBytes(16,ipAC, AUTH_PORT);       
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");
            byte[] encodedSecretCTGS = comunicator.getBytes(16,ipAC, AUTH_PORT);    
            SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");
            System.out.println("Llave Secreta Client: "+secretC);
            System.out.println("Claves recibidas y codificadas");
            
            //Manda (1)
            System.out.println(" ¬ Ingresa tu Usuario: ");
            String clientID = scanner.nextLine(); 
            
            System.out.println(" ¬ Ingresa la IP del Ticket-Granting-Server: ");
            InetAddress ipTGS = InetAddress.getByName(scanner.nextLine());
            String Str_ipTGS = ipTGS.toString();
            
            String ts1 = Instant.now().toString();
            
            String[] message_1_Array = {clientID,Str_ipTGS,ts1};
            String message_1 = Arrays.toString(message_1_Array);
            byte[] message_1_Bytes = message_1.getBytes("UTF8");
            
            //IDc
            System.out.println("Esperando al AS...");
            comunicator.sendBytes(AS_PORT, message_1_Bytes);          
            
            System.out.println("Se envió correctamente el mensaje (1)");
            
            //  Recibe (2)
            System.out.println(" ¬ Ingresa la IP del AS: ");
            InetAddress ipAS = InetAddress.getByName(scanner.nextLine());
            byte[] Emessage_2_Bytes = comunicator.getBytes(512,ipAS, AS_PORT);
            System.out.println(Emessage_2_Bytes.length);
            byte[] trimmed = conv.trim( Emessage_2_Bytes);
            System.out.println(trimmed.length);
            byte[] decryptedMessage2 = encryptor.AESDecryption(secretC, trimmed);
            String message_2 = new String(decryptedMessage2, StandardCharsets.UTF_8).replaceAll("[\\[\\]]", "");
            System.out.println(message_2);
            String[] message_2_Array = message_2.split(",");

            Kctgs = message_2_Array[0];
            System.out.println(Kctgs);
            byte[] KCTGSBytes = Kctgs.getBytes();
            SecretKey secretKCTGS = new SecretKeySpec(KCTGSBytes, 0, KCTGSBytes.length, "AES");
            IDtgs = message_2_Array[1];
            TS2 = message_2_Array[2];
            lifetime2 = message_2_Array[3];
            String ticketTGS = message_2_Array[4];
            
            System.out.println("Mensaje (2) Recibido");   
            
            //  Manda (3)
            System.out.println(" ¬ Ingresa la IP del Server del Servicio: ");
            InetAddress ipV = InetAddress.getByName(scanner.nextLine());
            String Str_ipV = ipV.toString();
            
            InetAddress ipC = InetAddress.getLocalHost();
            String Str_ipC = ipC.toString();
            
            String ts3 = Instant.now().toString();
            
            //Autentificador
            
            String[] auth_C1_Array = {clientID,Str_ipC,ts3};
            String auth_C1 = Arrays.toString(auth_C1_Array);

            byte[] E_K_CTGS_auth_C1_Bytes = encryptor.AESEncryption(secretCTGS, auth_C1);
            String E_K_CTGS_auth_C1 = new String(E_K_CTGS_auth_C1_Bytes, StandardCharsets.UTF_8);
            
            //  Mensaje (3)            
            
            String[] message_3_Array = {Str_ipV,ticketTGS,E_K_CTGS_auth_C1};
            String message_3 = Arrays.toString(message_3_Array);
            byte[] message_3_Bytes = message_3.getBytes();
            
            System.out.println("Esperando al TGS...");
            comunicator.sendBytes(TGS_PORT, message_3_Bytes);
                        
            //Recibe (4)
            System.out.println("4");
            byte[] encryptedMessage4 = comunicator.getBytes(512,ipTGS, TGS_PORT);
            byte[] decryptedMessage4 = encryptor.AESDecryption(secretKCTGS, encryptedMessage4);
            
            String decipheredArray4 = new String(decryptedMessage4, StandardCharsets.UTF_8);
            String [] decipheredData4 = decipheredArray4.split("||");

            String KCV = decipheredData4[0];
            byte[] KCVBytes= KCV.getBytes();
            SecretKey secretKCV = new SecretKeySpec(KCVBytes, 0, KCVBytes.length, "AES");
            
            String idV = decipheredData4[1];           
            String ts4 = decipheredData4[2];
            String ticketV = decipheredData4[3];
            
            //AuthC2V
            String ts5 = Instant.now().toString();

            String[] Auth_C2V_Array = {clientID,Str_ipC,ts5};
            String Auth_C2V = Arrays.toString(Auth_C2V_Array);
            
            byte[] K_CV_Auth_C2V_Bytes = encryptor.AESEncryption(secretKCV, Auth_C2V);
            String K_CV_Auth_C2V = new String(K_CV_Auth_C2V_Bytes, StandardCharsets.UTF_8);
            
            //  Mensaje (5)
            String[] message_5_Array = {ticketV,K_CV_Auth_C2V};
            String message_5 = Arrays.toString(Auth_C2V_Array);            
            byte[] message_5_Bytes = message_5.getBytes();
            
            comunicator.sendBytes(V_PORT, message_5_Bytes);
            
            System.out.println("Mensaje (5) Enviado");
            
            //Recibe (6)
            if(comunicator.getBytes(512,ipV, V_PORT)!=null){
                System.out.println("Servicio Concedido y Cliente autentificado!");
            }
            else{
                System.out.println("Servicio Denegado. Cliente no Autentificado");
            }            
        }
        catch(IOException ex){
            System.out.println(ex);
        }       
    }
}
