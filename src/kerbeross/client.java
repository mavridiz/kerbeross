package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class client {

    public static void main(String[] args) {
        int AUTH_PORT = 5000;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        
        try{
            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Cliente
            byte[] encodedSecretC = comunicator.getBytes(ipC, AUTH_PORT);       
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");
            
            System.out.println("Claves recibidas y codificadas");
            
        }
        catch(IOException ex){
            System.out.println(ex);
        }
    }
    
}
