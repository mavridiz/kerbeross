package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class Comunication {

    public void sendBytes(int port, byte[] message) {
        try {
            //  Abre un serverSocket, un dataSocket y envia los datos
            ServerSocket socket = new ServerSocket(port);
            System.out.println("Esperando al receptor...");

            Socket dataSocket = socket.accept();
            System.out.println("Conexion establecida");

            dataSocket.getOutputStream().write(message);
            dataSocket.getOutputStream().flush();
            dataSocket.close();
            socket.close();

        } catch (IOException ex) {
            System.out.println(ex);
        }
    }

    public byte[] getBytes(InetAddress ip, int port) throws IOException {
        //  Recibe los datos en bytes
        Socket socket = new Socket(ip, port);

        byte[] data = new byte[128];
        socket.getInputStream().read(data);
        socket.close();

        return data;
    }

}
