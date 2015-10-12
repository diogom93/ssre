"""
public class Server {
    static public void main(String[] args) {
        try {
            // Create server socket
            ServerSocket ss = new ServerSocket(4567);

            // Start upload counter
            int counter = 0;

            System.out.println("Server started ...");

            while(true) {
                // Wait for client
                Socket s = ss.accept();

                // Increment counter
                counter++;

                System.out.println("Accepted connection "+counter+".");

                // Open file to write to
                FileOutputStream fos = new FileOutputStream(args[0]+"/"+counter);

                // Get socket input stream
                InputStream sis = s.getInputStream();

                // Get file 50 bytes at a time
                byte[] buffer = new byte[50];
                int bytes_read = sis.read(buffer);
                while (bytes_read > 0) {
                   fos.write(buffer,0,bytes_read);
                   bytes_read = sis.read(buffer);
                }

                // Close socket
                s.close();
                System.out.println("Closed connection.");

                // Close file
                fos.close();
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
"""
