package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class TGS {

    public static void main(String[] args) {
        int AUTH_PORT = 5000;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        
        try{
            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del TGS
            byte[] encodedSecretTGS = comunicator.getBytes(ipC, AUTH_PORT);       
            SecretKey secretTGS = new SecretKeySpec(encodedSecretTGS, 0, encodedSecretTGS.length, "AES");

            //  Se recibe la Clave del Client/TGS
            byte[] encodedSecretCTGS = comunicator.getBytes(ipC, AUTH_PORT);       
            SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");
            
            //  Se recibe la Clave del Servidor
            byte[] encodedSecretV = comunicator.getBytes(ipC, AUTH_PORT);       
            SecretKey secretV = new SecretKeySpec(encodedSecretV, 0, encodedSecretV.length, "AES");  
            
            //  Se recibe la Clave del Client/Servidor
            byte[] encodedSecretCV = comunicator.getBytes(ipC, AUTH_PORT);       
            SecretKey secretCV = new SecretKeySpec(encodedSecretCV, 0, encodedSecretCV.length, "AES");              
            
            System.out.println("Claves recibidas y codificadas");
            
        }
        catch(IOException ex){
            System.out.println(ex);
        }
        
    }
    
}
