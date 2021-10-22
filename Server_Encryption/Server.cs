using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using Encryption_Library;

namespace Server_Encryption
{
    class Server
    {
        private TcpListener TcpListener;
        private RsaEncryption encryption;
        private int clientCount;

        public Server()
        {
            TcpListener = new TcpListener(new IPEndPoint(IPAddress.Any, 3001));
            TcpListener.Start();

            // Create and save key
            encryption = new RsaEncryption();
            encryption.SaveKey(encryption.publicKey, encryption.txtPath);

            clientCount = 0;

            Console.WriteLine("Server Started");

            BeginListening();
        }

        private void BeginListening()
        {
            while (true)
            {
                // Accecpt new client
                clientCount++;
                TcpClient tcpClient = TcpListener.AcceptTcpClient();
                Console.WriteLine("Client No: " + Convert.ToString(clientCount) + " connected!");

                // Handle client massage
                ClientHandler clientHandler = new ClientHandler(tcpClient, clientCount, encryption);
            }
        }
    }
}
