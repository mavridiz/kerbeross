package kerbeross;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AS {

    public static void main(String[] args) {
        int AUTH_PORT = 5000;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Converter conv = new Converter();
        
        try{
            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipAS = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Client
            byte[] encodedSecretC = comunicator.getBytes(ipAS, AUTH_PORT);       
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");

            //  Se recibe la Clave del Client/TGS
            byte[] encodedSecretCTGS = comunicator.getBytes(ipAS, AUTH_PORT);       
            SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");
            
            //  Se recibe la Clave del Client/TGS
            byte[] encodedSecretTGS = comunicator.getBytes(ipAS, AUTH_PORT);       
            SecretKey secretTGS = new SecretKeySpec(encodedSecretTGS, 0, encodedSecretTGS.length, "AES");  
            
            System.out.println("Claves recibidas y codificadas");
            
            //  Se conecta al Client
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());        
            
            //  Se conecta al TGS
            System.out.println(" ¬ Ingresa la IP del TGS: ");
            InetAddress ipTGS = InetAddress.getByName(scanner.nextLine()); 
            String Str_ipTGS = ipTGS.toString();
            byte[] TGSBytesC = Str_ipTGS.getBytes();
            
            //  Recibe (1)
            byte[] IDcBytes = comunicator.getBytes(ipC, AUTH_PORT);
            byte[] tgsBytesAS = comunicator.getBytes(ipC, AUTH_PORT);
            byte[] ts1Bytes = comunicator.getBytes(ipC, AUTH_PORT);
            
            //Se compara la ID del TGS
            
            if(tgsBytesAS!=TGSBytesC){
                System.out.println("Los ID's NO coinciden");
            }
            
            //  Crea (2)
            byte[]secretCTGSBytes = secretCTGS.getEncoded();
            Instant ts2 = Instant.now();
            byte[] tsBytes = conv.serialize(ts2);
            long lifeTime2 = 5;
            
            
            //  TicketTGS          
            
        }
        catch(IOException ex){
            System.out.println(ex);
        }
        
    }
    
}
