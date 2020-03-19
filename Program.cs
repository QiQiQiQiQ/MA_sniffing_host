using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Input;

namespace Sniffing
{
    /*
    public struct win_linux_header
    {
        public byte type;
        public byte flag;
        public ushort len;

        public static implicit operator win_linux_header(byte[] buffer)
        {
            return new win_linux_header() { type = buffer[0], flag = buffer[1], len = BitConverter.ToUInt16(buffer, 3) };
        }
    }
    class Constants
    {
        public const int rbuf_len = 8192;    // define the buffer length for receiving messages
        public const int sbuf_len = 256;    // define the buffer length for sending messages
        public const int pcaphdr_len = 16;
        public const int globalhdr_len = 24;
    }*/
    class FTYPE
    {
        public const byte READY_TO_SEND = 0x00;  //Ready to send frame
        public const byte SEND_REQ = 0x01;   //bit0 in reserved field: 0 - to send all, 1 - only secc/evcc frames
        public const byte STOP_REQ = 0x02;
        public const byte EXIT_REQ = 0x03;
        public const byte DATA_ACK = 0x04;
        public const byte STOP_ACK = 0x05;
        public const byte DATA = 0x10;
        public const byte GLOBAL_HEADER = 0x11;
        public const UInt32 magic_number_swapped = 0xd4c3b2a1;
        public const UInt32 magic_number_identical = 0xa1b2c3d4;
    }
    class FLAG
    {
        public const byte NONE = 0x00;
        /* bit mask */
        public const byte B1 = 0x01;
        public const byte B2 = 0x02;
        /* bit 0 */
        public const byte ALL = 0x01;
        public const byte EV_EVSE = 0x00;
        /* bit 1 */
        public const byte GLOBAL_HEADER = 0x02;
        public static bool global_hdr_exist(byte flag)
        {
            return ( (flag & (byte)0x02) == FLAG.GLOBAL_HEADER );
        }
    }
    class LEN
    {
        public const int GLOBAL_HDR = 24;
        public const int PKT_HDR = 16;
    }
    class USER_COMMAND
    {
        public const ConsoleKey REQ_ALL = ConsoleKey.A;
        public const ConsoleKey REQ_EV_EVSE = ConsoleKey.E;
        public const ConsoleKey EXIT = ConsoleKey.X;
        public const ConsoleKey STOP = ConsoleKey.S;
    }
    class IEEE80211
    {
        /* bit mask */
        public const UInt16 FCTL_FTYPE = 0x000c;
        public const UInt16 FCTL_STYPE = 0x00f0;
        /* frame type */
        public const UInt16 FTYPE_MGMT = 0x0000;
        public const UInt16 FTYPE_CTL = 0x0004;
        public const UInt16 FTYPE_DATA = 0x0008;
        public const UInt16 FTYPE_EXT = 0x000c;
        /* subtype - management */
        public const UInt16 STYPE_ASSOC_REQ = 0x0000;
        public const UInt16 STYPE_ASSOC_RESP = 0x0010;
        public const UInt16 STYPE_REASSOC_REQ = 0x0020;
        public const UInt16 STYPE_REASSOC_RESP = 0x0030;
        public const UInt16 STYPE_PROBE_REQ = 0x0040;
        public const UInt16 STYPE_PROBE_RESP = 0x0050;
        public const UInt16 STYPE_BEACON = 0x0080;
        public const UInt16 STYPE_ATIM = 0x0090;
        public const UInt16 STYPE_DISASSOC = 0x00a0;
        public const UInt16 STYPE_AUTH = 0x00b0;
        public const UInt16 STYPE_DEAUTH = 0x00c0;
        public const UInt16 STYPE_ACTION = 0x00d0;
        /* subtype - control */
        public const UInt16 STYPE_CTL_EXT = 0x0060;
        public const UInt16 STYPE_BACK_REQ = 0x0080;
        public const UInt16 STYPE_BACK = 0x0090;
        public const UInt16 STYPE_PSPOLL = 0x00a0;
        public const UInt16 STYPE_RTS = 0x00b0;
        public const UInt16 STYPE_CTS = 0x00c0;
        public const UInt16 STYPE_ACK = 0x00d0;
        public const UInt16 STYPE_CFEND = 0x00e0;
        public const UInt16 STYPE_CFENDACK = 0x00f0;
        /* subtype - data */
        public const UInt16 STYPE_DATA = 0x0000;
        public const UInt16 STYPE_DATA_CFACK = 0x0010;
        public const UInt16 STYPE_DATA_CFPOLL = 0x0020;
        public const UInt16 STYPE_DATA_CFACKPOLL = 0x0030;
        public const UInt16 STYPE_NULLFUNC = 0x0040;
        public const UInt16 STYPE_CFACK = 0x0050;
        public const UInt16 STYPE_CFPOLL = 0x0060;
        public const UInt16 STYPE_CFACKPOLL = 0x0070;
        public const UInt16 STYPE_QOS_DATA = 0x0080;
        public const UInt16 STYPE_QOS_DATA_CFACK = 0x0090;
        public const UInt16 STYPE_QOS_DATA_CFPOLL = 0x00a0;
        public const UInt16 STYPE_QOS_DATA_CFACKPOLL = 0x00b0;
        public const UInt16 STYPE_QOS_NULLFUNC = 0x00c0;
        public const UInt16 STYPE_QOS_CFACK = 0x00d0;
        public const UInt16 STYPE_QOS_CFPOLL = 0x00e0;
        public const UInt16 STYPE_QOS_CFACKPOLL = 0x00f0;
    }
    class BUFFER
    {
        public static byte[] send = new byte[256];
        public static byte[] receive = new byte[256];
        // buffers for data frame
        public static byte[] control_field = new byte[4];
        public static byte[] length_field = new byte[5];
        public static byte[] global_hdr = new byte[LEN.GLOBAL_HDR];
        public static byte[] packet_hdr = new byte[LEN.PKT_HDR];
        public static byte[] radiotap_hdr = new byte[128];
        public static byte[] ieee80211_frame = new byte[8192];
    }
    class Program
    {
        // general buffers
        private static byte[] buf_send = new byte[256];
        private static byte[] buf_receive = new byte[10000];
        // buffers for for individual fields
        private static byte[] buf_control_field = new byte[4];
        private static byte[] buf_length_field = new byte[5];
        private static byte[] buf_global_hdr = new byte[LEN.GLOBAL_HDR];
        private static byte[] buf_packet_hdr = new byte[LEN.PKT_HDR];
        private static byte[] buf_radiotap_hdr = new byte[128];
        private static byte[] buf_ieee80211_frame = new byte[8192];

        private static Socket clientSocket;
        private static UInt16 packet_nr = 0;
        private static UInt16 len_radiotap;
        private static byte len_MAC;
        private static UInt16 len_frame_body;

        static void Main(string[] args)
        {
            // open socket
            Open_Socket();
            
            // wait for client to get ready
            if (!Wait_For_ReadyToSend())
            {
                Console.WriteLine("error on Receiving Ready to Send frame");
                return;
            }
            else
            {
                Console.WriteLine("client ready to send");
                Thread.Sleep(1000);
            }
            
            ConsoleKeyInfo cki;
            while (true)
            {
                Show_Usage();
                // sniffer not running, wait for user command and handle it
                while (true)
                {
                    if(Console.KeyAvailable == true)
                    {
                        cki = Console.ReadKey(true);
                        if (cki.Key == USER_COMMAND.REQ_ALL)
                        {
                            Console.WriteLine("request all");
                            Send_to_client(FTYPE.SEND_REQ, FLAG.ALL, null);
                            break;
                        }
                        else if (cki.Key == USER_COMMAND.REQ_EV_EVSE)
                        {
                            Console.WriteLine("request EV/EVSE frames");
                            Send_to_client(FTYPE.SEND_REQ, FLAG.EV_EVSE, null);
                            break;
                        }
                        else if (cki.Key == USER_COMMAND.EXIT)
                        {
                            Console.WriteLine("conncetion shutdown, press any key to exit program...");
                            Send_to_client(FTYPE.EXIT_REQ, FLAG.NONE, null);
                            clientSocket.Close();
                            Console.ReadKey();
                            return;
                        }
                        else
                        {
                            Console.WriteLine("invalid key");
                            Thread.Sleep(1000);
                        }
                    }
                    else
                    {
                        Thread.Sleep(1000);
                    }
                }

                // execute sniffing
                while( Process_a_frame()) { }
            }
            
        }

        public static void Open_Socket()
        {
            /* acquire proper ip address and port */
            int port;
            Console.WriteLine("Please enter a port number between 2000 and 65535");
            string port_str = Console.ReadLine();
            port = Int16.Parse(port_str);
            while (port < 2000 || port > 65535)
            {
                Console.WriteLine("invalid port, please enter again");
                port_str = Console.ReadLine();
                port = Int16.Parse(port_str);
            }
            IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
            for (int i = 1; i <= ipHost.AddressList.Length; i++)
            {
                Console.WriteLine("ip {0}: {1}", i, ipHost.AddressList[i - 1].ToString());
            }
            Console.WriteLine("Please enter the index of the ip address you want to use");
            string index = Console.ReadLine();
            int ip_index = Int16.Parse(index) - 1;
            IPAddress ipAddr = ipHost.AddressList[ip_index];
            Console.WriteLine("Host ip address: {0}", ipAddr.ToString());

            /* create socket */
            IPEndPoint localEndPoint = new IPEndPoint(ipAddr, port);
            Socket listener = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                /* bind socket */
                listener.Bind(localEndPoint);
                listener.Listen(5);
                Console.WriteLine("Waiting connection ...");
                clientSocket = listener.Accept();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return;
        }

        public static void read_and_print(Socket sock)
        {
            /* test code */
            try
            {
                int num;
                while (true)
                {
                    Array.Clear(BUFFER.receive, 0, 256);
                    if(sock.Available > 31)
                    {
                        num = sock.Receive(BUFFER.receive, 32, SocketFlags.None);
                        Print_Content(BUFFER.receive, 0, num);
                        continue;
                    }
                    else
                    {
                        Thread.Sleep(3000);
                        if(sock.Available < 32)
                        {
                            num = sock.Receive(BUFFER.receive, sock.Available, SocketFlags.None);
                            Print_Content(BUFFER.receive, 0, num);
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        private static void Print_Content(byte[] field, int start, int end)
        {
            if (start > end)
                return;
            for (int i = start; i < end; i++)
            {
                if (((i-start) % 8) == 0)
                {
                    if (i == start)
                        Console.Write("\t");
                    else if ((i - start) % 32 == 0)
                        Console.Write("\n\t");
                    else
                        Console.Write(" ");
                }
                Console.Write("{0} ", field[i].ToString("x2"));
            }
            return;
        }

        private static void Show_Usage()
        {
            Console.WriteLine("\nEnter Command by pressing the Keyboard: ");
            Console.Write("X - Exit, S - stop, A - request all frame, E - request frames from EV_EVSE");
            return;
        }

        private static void Send_to_client(byte type, byte flag, byte[] frame_body)
        {
            Array.Clear(buf_send, 0, buf_send.Length);
            buf_send[0] = type;
            buf_send[1] = flag;
            if (frame_body != null)
            {
                ushort len = (ushort)frame_body.GetLength(0);
                byte[] length = BitConverter.GetBytes(len);
                Array.Reverse(length);
                length.CopyTo(buf_send, 2);
                frame_body.CopyTo(buf_send, 4);
                clientSocket.Send(buf_send, 0, (int)(4 + len), SocketFlags.None);
            }
            else
            {
                ushort len = 0x0000;
                byte[] length = BitConverter.GetBytes(len);
                Array.Reverse(length);
                length.CopyTo(buf_send, 2);
                clientSocket.Send(buf_send, 0, 4, SocketFlags.None);
            }
            return;
        }

        private static void Write_to_logfile(byte[] buffer)
        {
            return;
        }

        private static bool Wait_For_ReadyToSend()
        {
            while (true)
            {
                Thread.Sleep(1000);
                if(clientSocket.Available >= 4)
                {
                    Array.Clear(buf_control_field, 0, buf_control_field.Length);
                    clientSocket.Receive(buf_control_field, 0, 4, SocketFlags.None);
                    if (buf_control_field[0] == FTYPE.READY_TO_SEND)
                        return true;
                    else
                        return false;   // return false on error
                }
            }
        }

        private static string Get_ieee80211_type(ushort fc)
        {
            if ( (fc & IEEE80211.FCTL_FTYPE) == IEEE80211.FTYPE_CTL )
            {
                if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_ACK)
                    return "Acknowledge";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_RTS)
                    return "Request to Send";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CTS)
                    return "Clear to Send";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CTL_EXT)
                    return "ctl ext";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_BACK)
                    return "Block Acknowledge";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_BACK_REQ)
                    return "Block Acknowledge request";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_PSPOLL)
                    return "power save poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CFEND)
                    return "cf-end";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CFENDACK)
                    return "cf-end & cf-ack";
                else
                    return "unknown control frame";
            }
            else if ((fc & IEEE80211.FCTL_FTYPE) == IEEE80211.FTYPE_MGMT)
            {
                if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_ASSOC_REQ)
                    return "association request";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_ASSOC_RESP)
                    return "association response";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_REASSOC_RESP)
                    return "reassociation request";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_REASSOC_RESP)
                    return "reassociation response";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_PROBE_REQ)
                    return "probe request";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_PROBE_RESP)
                    return "probe response";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_BEACON)
                    return "beacon";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_ATIM)
                    return "atim";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DISASSOC)
                    return "disassociation";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_AUTH)
                    return "authentication";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DEAUTH)
                    return "deauthentication";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_ACTION)
                    return "action";
                else
                    return "unknown management frame";
            }
            else if ((fc & IEEE80211.FCTL_FTYPE) == IEEE80211.FTYPE_DATA)
            {
                if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DATA)
                    return "data";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DATA_CFACK)
                    return "data cf ack";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DATA_CFPOLL)
                    return "data cf poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_DATA_CFACKPOLL)
                    return "data cf ack poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_NULLFUNC)
                    return "nullfunc";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CFACK)
                    return "cf ack";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CFPOLL)
                    return "cf poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_CFACKPOLL)
                    return "cf ack poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_DATA)
                    return "QoS data";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_DATA_CFACK)
                    return "QoS data cf ack";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_DATA_CFPOLL)
                    return "QoS data cf poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_DATA_CFACKPOLL)
                    return "QoS data cf ack poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_NULLFUNC)
                    return "QoS null";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_CFACK)
                    return "QoS cf ack";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_CFPOLL)
                    return "QoS cf poll";
                else if ((fc & IEEE80211.FCTL_STYPE) == IEEE80211.STYPE_QOS_CFACKPOLL)
                    return "QoS cf ack poll";
                else
                    return "unknown data frame";
            }
            else
            {
                return "EXT frame";
            }
        }

        private static void Wait_For_Datastream(int size, string to_display)
        {
            /* wait until enough data available. When interrupted by STOP command a true value will be returned */
            int timer = 0;
            while (clientSocket.Available < size)
            {
                Thread.Sleep(200);
                timer++;
                /*
                if (Console.KeyAvailable == true)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(true);
                    if (cki.Key == USER_COMMAND.STOP)
                    {
                        Send_to_client(clientSocket, FTYPE.STOP_REQ, FLAG.NONE, null);
                        return true;
                    }
                    else if ((cki.Key == USER_COMMAND.REQ_ALL) && (req_flag != FLAG.ALL))
                    {
                        req_flag = FLAG.ALL;
                        Send_to_client(clientSocket, FTYPE.SEND_REQ, FLAG.ALL, null);
                    }
                    else if ((cki.Key == USER_COMMAND.REQ_EV_EVSE) && (req_flag != FLAG.EV_EVSE))
                    {
                        req_flag = FLAG.EV_EVSE;
                        Send_to_client(clientSocket, FTYPE.SEND_REQ, FLAG.EV_EVSE, null);
                    }
                }
                */
                if (timer % 15 == 0)
                {
                    Console.WriteLine("waiting for '{0}'...", to_display);
                }
            }
            return;
        }

        private static bool Process_a_frame()
        {
            /*** receive and process one frame, if terminated by the STOP command, return true ***/

            /* receive the control field */
            Wait_For_Datastream(4, "control field");
            Array.Clear(buf_control_field, 0, buf_control_field.Length);
            clientSocket.Receive(buf_control_field, 4, SocketFlags.None);
            byte R_type = buf_control_field[0];
            byte R_flag = buf_control_field[1];
            UInt16 R_length = BitConverter.ToUInt16(buf_control_field, 2);

            /* receive and analyse the frame body field */
            if (R_type == FTYPE.GLOBAL_HEADER)
            {
                Array.Clear(buf_global_hdr, 0, buf_global_hdr.Length);
                clientSocket.Receive(buf_global_hdr, 24, SocketFlags.None);
                Send_to_client(FTYPE.DATA_ACK, FLAG.NONE, null);
                Console.WriteLine("**********************************************\nPCAP Global header");
                Print_Content(buf_global_hdr, 0, 24);
                Write_to_logfile(buf_global_hdr);
            }
            else if ( R_type == FTYPE.DATA )
            {
                // length field
                Wait_For_Datastream(5, "length field");
                Array.Clear(buf_length_field, 0, buf_length_field.Length);
                clientSocket.Receive(buf_length_field, 5, SocketFlags.None);
                len_radiotap = BitConverter.ToUInt16(buf_length_field, 0);
                len_MAC = buf_length_field[2];
                len_frame_body = BitConverter.ToUInt16(buf_length_field, 3);

                // PCAP packet header
                Wait_For_Datastream(LEN.PKT_HDR, "PCAP packet header " + packet_nr.ToString());
                Array.Clear(buf_packet_hdr, 0, buf_packet_hdr.Length);
                clientSocket.Receive(buf_packet_hdr, LEN.PKT_HDR, SocketFlags.None);
                Write_to_logfile(buf_packet_hdr);

                // radiotap header
                Wait_For_Datastream((int)len_radiotap, "radiotap header");
                Array.Clear(buf_radiotap_hdr, 0, buf_radiotap_hdr.Length);
                clientSocket.Receive(buf_radiotap_hdr, (int)len_radiotap, SocketFlags.None);
                Write_to_logfile(buf_radiotap_hdr);

                // IEEE80211 frame
                Wait_For_Datastream((int)(R_length - len_radiotap), "IEEE80211 packet " + packet_nr.ToString());
                Array.Clear(buf_ieee80211_frame, 0, buf_ieee80211_frame.Length);
                clientSocket.Receive(buf_ieee80211_frame, (int)(R_length - len_radiotap), SocketFlags.None);
                Write_to_logfile(buf_ieee80211_frame);
                
                // send ack data
                if(Console.KeyAvailable == true)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(true);
                    if (cki.Key == USER_COMMAND.STOP)
                    {
                        Send_to_client(FTYPE.STOP_REQ, FLAG.NONE, null);
                        return false;
                    }
                    else
                    {
                        Send_to_client(FTYPE.DATA_ACK, FLAG.NONE, null);
                    }
                }
                else
                {
                    Send_to_client(FTYPE.DATA_ACK, FLAG.NONE, null);
                }
                /* parse */
                Console.WriteLine("\n**********************************************");
                Console.WriteLine("packet {0}\tlength {1}\t{2}\n", ++packet_nr, R_length, Get_ieee80211_type(BitConverter.ToUInt16(buf_ieee80211_frame, 0)));
                //Console.WriteLine("radiotap header:");
                //Print_Content(buf_radiotap_hdr, 0, len_radiotap);
                Console.WriteLine("MAC header:");
                Print_Content(buf_ieee80211_frame, 0, len_MAC);
                Console.WriteLine("\nframe body:");
                Print_Content(buf_ieee80211_frame, len_MAC, len_MAC+len_frame_body);
                Console.WriteLine("\nFCS:");
                Print_Content(buf_ieee80211_frame, len_MAC+len_frame_body-4, len_MAC+len_frame_body);
            }
            else
            {
                Array.Clear(BUFFER.receive, 0, BUFFER.receive.Length);
                Wait_For_Datastream(R_length, "windows-linux control frame");
                clientSocket.Receive(BUFFER.receive, R_length, SocketFlags.None);
            }
            Thread.Sleep(500);
            return true;
        }
        /*
        private static int Wait_for_Command()
        {
            Console.WriteLine("Press Key to continue: X - Exit, A - request all frame, E - request frames from EV_EVSE");
            while (true)
            {
                if(Console.KeyAvailable == true)
                {
                    ConsoleKeyInfo cki = Console.ReadKey(true);
                    if (cki.Key == USER_COMMAND.EXIT)
                    {
                        Send_to_client(FTYPE.EXIT_REQ, FLAG.NONE, null);
                        clientSocket.Close();
                        Console.WriteLine("Socket closed");
                        return 0;
                    }
                    else if (cki.Key == USER_COMMAND.REQ_ALL)
                    {
                        req_flag = FLAG.ALL;
                        Send_to_client(FTYPE.SEND_REQ, FLAG.ALL, null);
                        return 1;
                    }
                    else if (cki.Key == USER_COMMAND.REQ_EV_EVSE)
                    {
                        req_flag = FLAG.EV_EVSE;
                        Send_to_client(FTYPE.SEND_REQ, FLAG.EV_EVSE, null);
                        return 2;
                    }
                    else
                        Thread.Sleep(500);
                }
                else
                    Thread.Sleep(500);
            }
        }
        */
        private static void test(Socket sock)
        {
            /* test code */
            /*
            UInt32 data = 0xa1b2c3d4;
            byte[] send_u8 = BitConverter.GetBytes(data);
            byte[] read_u8 = new byte[4];
            int num;
            while (true)
            {
                Thread.Sleep(2000);
                num = clientSocket.Send(send_u8, 0, send_u8.Length, SocketFlags.None);
                Console.Write("Send: {0} {1} {2} {3}\n", send_u8[0].ToString("x2"), send_u8[1].ToString("x2"), send_u8[2].ToString("x2"), send_u8[3].ToString("x2"));
                while (clientSocket.Available < 4) { }
                num = clientSocket.Receive(read_u8, 0, 4, SocketFlags.None);
                Console.Write("Read: {0} {1} {2} {3}\n", read_u8[0].ToString("x2"), read_u8[1].ToString("x2"), read_u8[2].ToString("x2"), read_u8[3].ToString("x2"));
                Console.ReadKey(true);
            }
            */
            while (true)
            {
                int num = sock.Receive(buf_receive, sock.Available, SocketFlags.None);
                Print_Content(buf_receive, 0, num);
                while (Console.KeyAvailable == false)
                {

                }
                Console.ReadKey();
                Send_to_client(FTYPE.DATA_ACK, FLAG.NONE, null);
            }
        }
    }
}
