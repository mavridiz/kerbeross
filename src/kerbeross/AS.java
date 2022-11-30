package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AS {

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        int AUTH_PORT = 5000, AS_C_PORT = 5003;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Encryptor cryptor = new Encryptor();

        try {
            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipAS = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Client
            byte[] encodedSecretC = comunicator.getBytes(ipAS, AUTH_PORT);
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");

            //  Se recibe la Clave del Client/TGS
            byte[] encodedSecretCTGS = comunicator.getBytes(ipAS, AUTH_PORT);
            SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");

            //  Se recibe la Clave del TGS
            byte[] encodedSecretTGS = comunicator.getBytes(ipAS, AUTH_PORT);
            SecretKey secretTGS = new SecretKeySpec(encodedSecretTGS, 0, encodedSecretTGS.length, "AES");

            System.out.println("Claves recibidas y codificadas");

            //  Se conecta al Client
            System.out.println(" ¬ Ingresa la IP del cliente: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());

            //  Obtiene el ID del TGS
            System.out.println(" ¬ Ingresa la IP del TGS: ");
            InetAddress ipTGS = InetAddress.getByName(scanner.nextLine());
            String Str_ipTGS = ipTGS.toString();
            byte[] TGSBytesC = Str_ipTGS.getBytes();

            //  Recibe (1)
            byte[] message_1_Bytes = comunicator.getBytes(ipC, AUTH_PORT);
            String message_1 = new String(message_1_Bytes, StandardCharsets.UTF_8);
            String[] message_1_Array = message_1.split("||");

            String ID_C, ID_TGS, TS_1;

            ID_C = message_1_Array[0];
            ID_TGS = message_1_Array[1];
            TS_1 = message_1_Array[2];
            
            String TS_2, LT_2, AD_C, K_C_TGS;

            TS_2 = Instant.now().toString();
            LT_2 = "5";
            AD_C = ipC.getHostAddress();
            K_C_TGS = new String(encodedSecretCTGS, StandardCharsets.UTF_8);

            // Se crea E_K_TGS_TICKET_TGS
            String[] ticket_TGS_Array = {K_C_TGS, ID_C, AD_C, ID_TGS, TS_2, LT_2};
            String ticket_TGS = ticket_TGS_Array.toString();
            byte[] E_K_TGS_Ticket_TGS_Bytes = cryptor.AESEncryption(secretTGS, ticket_TGS);
            String E_K_TGS_Ticket_TGS = new String(E_K_TGS_Ticket_TGS_Bytes, StandardCharsets.UTF_8);

            // Se crea (2)
            String[] message_2_Array = {K_C_TGS, ID_TGS, TS_2, LT_2, E_K_TGS_Ticket_TGS};
            String message_2 = message_2_Array.toString();
            byte[] E_K_C_message_2_Bytes = cryptor.AESEncryption(secretC, message_2);

            comunicator.sendBytes(AS_C_PORT, E_K_C_message_2_Bytes);

            //  TicketTGS          
        } catch (IOException ex) {
            System.out.println(ex);
        }

    }

}
