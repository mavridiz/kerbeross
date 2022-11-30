package kerbeross;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class client {

    public static void main(String[] args) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        int AUTH_PORT = 5000;
        int AS_PORT = 5000;
        int TGS_PORT = 5000;
        int V_PORT = 5000;
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
            byte[] encodedSecretC = comunicator.getBytes(ipAC, AUTH_PORT);       
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");
            
            System.out.println("Claves recibidas y codificadas");
            
            //Manda (1)
            System.out.println(" ¬ Ingresa tu Usuario: ");
            String clientID = scanner.nextLine(); 
            byte[] IDcBytes = clientID.getBytes();
            
            System.out.println(" ¬ Ingresa la IP del Ticket-Granting-Server: ");
            InetAddress ipTGS = InetAddress.getByName(scanner.nextLine());
            String Str_ipTGS = ipTGS.toString();
            byte[] ipTGSBytes = Str_ipTGS.getBytes();
            
            Instant ts1 = Instant.now();
            byte[] tsBytes = conv.serialize(ts1);
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(IDcBytes);
            outputStream.write(ipTGSBytes);
            outputStream.write(tsBytes);

            byte[] message1 = outputStream.toByteArray();     
            
            //IDc
            comunicator.sendBytes(AS_PORT, message1);
            
            System.out.println("Se envió correctamente el mensaje (1)");
            
            //  Recibe (2)
            byte[] encryptedMessage2 = comunicator.getBytes(ipAC, AS_PORT);
            byte[] decryptedMessage2 = encryptor.AESDecryption(secretC, encryptedMessage2);
            
            String cipheredData = decryptedMessage2.toString();

            Kctgs = cipheredData.substring(0, 16);
            byte[] KCTGSBytes= Kctgs.getBytes();
            SecretKey secretKCTGS = new SecretKeySpec(KCTGSBytes, 0, KCTGSBytes.length, "AES");
            IDtgs = cipheredData.substring(16,32);
            TS2 = cipheredData.substring(32,64);
            lifetime2 = cipheredData.substring(32,64);
            byte[] ticketTGS = cipheredData.substring(64,128).getBytes();
            
            //  Manda (3)
            System.out.println(" ¬ Ingresa la IP del Server del Servicio: ");
            InetAddress ipV = InetAddress.getByName(scanner.nextLine());
            String Str_ipV = ipV.toString();
            byte[] ipVBytes = Str_ipV.getBytes();
            
            InetAddress ipC = InetAddress.getLocalHost();
            String Str_ipC = ipC.toString();
            byte[] ipCBytes = Str_ipC.getBytes();
            
            Instant ts3 = Instant.now();
            byte[] ts3Bytes = conv.serialize(ts3);
            
            //Autentificador
             ByteArrayOutputStream os3 = new ByteArrayOutputStream();
            os3.write(clientID.getBytes());
            os3.write(ipCBytes);
            os3.write(ts3Bytes);

            byte[] DauthC = os3.toByteArray();
            
            byte[] EauthC = encryptor.AESEncryption(secretKCTGS, Arrays.toString(DauthC));
            
            ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
            outputStream2.write(ipVBytes);
            outputStream2.write(ticketTGS);
            outputStream2.write(EauthC);

            byte[] message3 = outputStream2.toByteArray();                 
            
            comunicator.sendBytes(TGS_PORT, message3);
            
            
            //Recibe (4)
            byte[] encryptedMessage4 = comunicator.getBytes(ipTGS, TGS_PORT);
            byte[] decryptedMessage4 = encryptor.AESDecryption(secretKCTGS, encryptedMessage4);
            
            String cipheredData4 = decryptedMessage4.toString();

            String KCV = cipheredData.substring(0, 16);
            byte[] KCVBytes= KCV.getBytes();
            SecretKey secretKCV = new SecretKeySpec(KCVBytes, 0, KCVBytes.length, "AES");
            
            String idV = cipheredData4.substring(16, 32);           
            String ts4 = cipheredData4.substring(32, 64);
            byte[] ticketV = cipheredData4.substring(64,128).getBytes();
            
            //AuthC2V
            Instant ts5 = Instant.now();
            byte[] ts5Bytes = conv.serialize(ts5);
            
            ByteArrayOutputStream os6 = new ByteArrayOutputStream();
            os6.write(clientID.getBytes());
            os6.write(ipCBytes);
            os6.write(ts5Bytes);

            byte[] DauthCV = os6.toByteArray();  
            
            byte[] EauthCV = encryptor.AESEncryption(secretKCV, Arrays.toString(DauthCV));
            
            ByteArrayOutputStream os5 = new ByteArrayOutputStream();
            os5.write(ticketV);
            os5.write(EauthCV);

            byte[] message5 = os5.toByteArray();              
            System.out.println("Mensaje (5) Enviado");
            
            //Recibe (6)
            if(comunicator.getBytes(ipV, V_PORT)!=null){
                System.out.println("Servicio Concedido y Cliente autentificado!");
            }
            
        }
        catch(IOException ex){
            System.out.println(ex);
        }
        
    }
}
