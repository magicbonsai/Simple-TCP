#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"
#include "tcpstate.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

#define BASIC_TIMEOUT 1
#define DEFAULT_Timertries 3

enum flag_states {
  SYN = 0,
  ACK = 1,
  FIN = 2,
  SYN_ACK = 3,
  RST = 4
 };

Packet Create_Packet(ConnectionToStateMapping<TCPState> conn, Buffer payload, unsigned int flag_states, unsigned int seq_num){
  Packet p;
  if (payload.GetSize() > 0) p = Packet(payload);

  IPHeader iph;
  iph.SetSourceIP(conn.connection.src);
  iph.SetDestIP(conn.connection.dest);
  iph.SetProtocol(conn.connection.protocol);
  iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + payload.GetSize());
  p.PushFrontHeader(iph);

  TCPHeader tcph;
  tcph.SetSourcePort(conn.connection.srcport, p);
  tcph.SetDestPort(conn.connection.destport, p);
  tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, p);
  tcph.SetWinSize(conn.state.GetRwnd(), p); // TCP_BUFFER_SIZE - RecvBuffer.GetSize();
  tcph.SetUrgentPtr(0, p);

  tcph.SetAckNum(conn.state.GetLastRecvd(), p);
  //@TODO is resent
  tcph.SetSeqNum(seq_num, p);

  unsigned char flags = 0;
  switch (flag_states) {
    case SYN:
        {
            SET_SYN(flags);
            tcph.SetAckNum(0, p);
        }
        break;

    case ACK: SET_ACK(flags); break;
    case FIN:
        {
            SET_FIN(flags);
            SET_ACK(flags);
        }
        break;
    case SYN_ACK:
        {
            SET_SYN(flags);
            SET_ACK(flags);
        }
        break;
    case RST: SET_RST(flags); break;
  }
  tcph.SetFlags(flags, p);

  tcph.RecomputeChecksum(p);

  unsigned int seq_num_test;
  tcph.GetSeqNum(seq_num_test);

  cerr << "tcp.GetSeqNum()" << seq_num_test << endl;
  p.PushBackHeader(tcph);

  return p;
}

int init_minet(MinetHandle &mux, MinetHandle &sock) {
  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  return 0;
}

void send_no_connection_error(IPHeader iph, Packet p, MinetHandle mux) {
  MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
  IPAddress source; iph.GetSourceIP(source);
  ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
  MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
  MinetSend(mux, error);
}

void set_connection(Connection &c, IPHeader iph, TCPHeader tcph){
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
}

Buffer get_payload_data(IPHeader iph, TCPHeader tcph, Packet p) {
  unsigned short len;
  iph.GetTotalLength(len);

  unsigned char IPHeaderLen;
  iph.GetHeaderLength(IPHeaderLen);
  len -= IPHeaderLen * 4;

  unsigned char TCPHeaderLen;
  tcph.GetHeaderLen(TCPHeaderLen);
  len -= TCPHeaderLen * 4;

  return p.GetPayload().ExtractFront(len);
}


int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
  if (init_minet(mux, sock) == -1) return -1;

  ConnectionList<TCPState> clist;
  MinetEvent event;
  double timeout = BASIC_TIMEOUT;

  // KY: The timeout in MinetGetNextEvent is the same as timeout in select
  while (MinetGetNextEvent(event, timeout)==0) {
    // if we received an unexpected type of event, print error
    // cerr << difftime(Time(), Time() + Time(BASIC_TIMEOUT)) << endl; // -1
    // cerr << difftime(Time() + Time(BASIC_TIMEOUT), Time()) << endl;  // 1
    // cerr << difftime(Time(BASIC_TIMEOUT), Time(BASIC_TIMEOUT)) << endl; // 0
    // cerr << Time() << " " << Time() + Time() << " " << Time(-1) << endl;


    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {

        if (event.eventtype == MinetEvent::Timeout){

            ConnectionList<TCPState>::iterator earliest = clist.FindEarliest();
            //cerr << "Time() :" << Time() << " earliest->timeout :" << earliest->timeout << endl;

            //cerr << "difftime(Time(), earliest->timeout) :" << difftime(Time(), earliest->timeout) << endl;

            while (earliest != clist.end()) {

              // cerr << "difftime(Time(), earliest->timeout)" << difftime(Time(), earliest->timeout) << endl;
              // cerr << earliest->state.last_sent << "  " << earliest->state.last_acked << endl;

              if (difftime(Time(), earliest->timeout) < 1) break;
              if (earliest->state.last_sent <= earliest->state.last_acked) {
                  earliest->timeout = Time() + Time(3600);
              }


              cerr << "In the difftime while loop" << endl;
              //cerr << "difftime(Time(), earliest->timeout) :" << difftime(Time(), earliest->timeout) << endl;


              switch (earliest->state.GetState()) {
                case SYN_SENT :
                  {
                      cerr << "In SYN_SENT Timeout" << endl;

                      MinetSend(mux, Create_Packet(*earliest, Buffer(), SYN, earliest->state.last_sent - 1));
                      earliest->timeout = Time() + Time(BASIC_TIMEOUT);
                  }
                  break;
                case LISTEN :
                    cerr << "In LISTEN Timeout, Impossible !!" << endl;
                    break;
                case SYN_RCVD :
                    {
                        cerr << "In SYN_RCVD Timeout" << endl;
                        MinetSend(mux, Create_Packet(*earliest, Buffer(), SYN_ACK, earliest->state.last_sent - 1));
                        earliest->timeout = Time() + Time(BASIC_TIMEOUT);
                    }
                    break;
                case FIN_WAIT1 :
                    {
                        cerr << "In FIN_WAIT1 Timeout" << endl;
                        MinetSend(mux, Create_Packet(*earliest, Buffer(), FIN, earliest->state.last_sent - 1));
                        earliest->timeout = Time() + Time(BASIC_TIMEOUT);
                    }
                    break;

                case LAST_ACK:
                    {
                        cerr << "In LAST_ACK Timeout" << endl;
                        MinetSend(mux, Create_Packet(*earliest, Buffer(), FIN, earliest->state.last_sent - 1));
                        earliest->timeout = Time() + Time(BASIC_TIMEOUT);
                    }
                    break;
                case TIME_WAIT:
                    {
                        cerr<< "In TIME_WAIT Timeout, Close the sock" << endl;
                        MinetSend(sock, SockRequestResponse(CLOSE, earliest->connection, Buffer(), 0, EOK));
                        earliest->state.SetState(CLOSE);
                        clist.erase(earliest);
                    }
                    break;
                case ESTABLISHED:
                    {

                        unsigned int offset = 0;
                        unsigned int last_sent_in_timeout = earliest->state.last_acked;

                        while (offset < earliest->state.SendBuffer.GetSize() && offset < earliest->state.N){

                            size_t size = TCP_MAXIMUM_SEGMENT_SIZE;

                            if (earliest->state.SendBuffer.GetSize() - offset < size){
                                size = earliest->state.SendBuffer.GetSize() - offset;
                            }
                            char send_data[TCP_MAXIMUM_SEGMENT_SIZE + 50];

                            earliest->state.SendBuffer.GetData(send_data, size, offset);

                            MinetSend(mux, Create_Packet(*earliest, Buffer(send_data, size), ACK, last_sent_in_timeout));
                            offset += size;
                            last_sent_in_timeout += size;
                        }
                        earliest->timeout = Time() + Time(BASIC_TIMEOUT);
                    }
                    break;
                default :
                    break;
              }
              earliest = clist.FindEarliest();
           }
      } else {
          MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
      }
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);

        IPHeader iph=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);


        //@TODO: Checksumok
        // bool checksumok=tcph.IsCorrectChecksum(p);

        Connection c;
        set_connection(c, iph, tcph);

        cerr <<"In mux, Clist size: "<< clist.size() <<endl;

        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);


        if (cs!=clist.end()) {
          Buffer data = get_payload_data(iph, tcph, p);

          unsigned char flags;  tcph.GetFlags(flags);
          unsigned int seq_num; tcph.GetSeqNum(seq_num);
          unsigned int ack_num; tcph.GetAckNum(ack_num);


          if (cs->state.last_sent != 0 && cs->state.last_sent < ack_num) {
            cerr << "== How could acknum lager than last send!!==" << endl;
            cerr << "cs->state.last_sent :" << cs->state.last_sent << " ack_num :" << ack_num << endl;
          }

          if (cs->state.last_acked < ack_num) {
             if (cs->state.GetState() == ESTABLISHED) {

                cs->state.SendBuffer.Erase(0, ack_num - cs->state.last_acked);

                unsigned int packet_on_the_fly = cs->state.last_sent - ack_num;
                unsigned int packet_can_sent = cs->state.N - packet_on_the_fly;
                unsigned int offset = packet_on_the_fly;


                while (offset < cs->state.SendBuffer.GetSize() && offset < cs->state.N){

                    size_t size = TCP_MAXIMUM_SEGMENT_SIZE;

                    if (cs->state.SendBuffer.GetSize() - offset < size){
                        size = cs->state.SendBuffer.GetSize() - offset;
                    }
                    char send_data[TCP_MAXIMUM_SEGMENT_SIZE + 50];

                    cs->state.SendBuffer.GetData(send_data, size, offset);


                    // cerr << "!!!Buffer :" << cs->state.SendBuffer << endl;
                    // cerr << "!!!Buffer Size:" << cs->state.SendBuffer.GetSize() << "  offset :" << offset << " last_sent :" << cs->state.last_sent << " last_acked :" << cs->state.last_acked << " size :" << size << endl;
                    // cerr << "!!!Send Buffer:" << send_data << endl;


                    MinetSend(mux, Create_Packet(*cs, Buffer(send_data, size), ACK, cs->state.last_sent));
                    offset += size;
                    cs->state.last_sent += size;
                }

                cs->timeout = Time() + Time(BASIC_TIMEOUT);
             }
             cs->state.last_acked = ack_num;
          }

          if (cs->state.last_recvd != 0 && cs->state.last_recvd !=seq_num) {
              cerr << "== OUT OF ORDER PACKET, DROP !! ==" << endl;
              cerr << "last_recvd :" << cs->state.last_recvd << endl;
              cerr << "seq_num" << seq_num << endl;
              continue;
          }

          switch (cs->state.GetState()) {
            case CLOSED :
              // Nothing
              cerr << "In CLOSE" <<endl;

              break;
            case LISTEN :
              // Wati for the first SYN
              // Important, create a new connection for this SYN, we can handle multiple connection at same time
              // SEND SYN+ACK
              // go to SYN_RCVD
              {
                  //cerr << "In LISTEN" << endl;
                  if (IS_SYN(flags)) {

                    TCPState tcp_state(0, SYN_RCVD, DEFAULT_Timertries);
                    ConnectionToStateMapping<TCPState>
                        conn(c, Time() + Time(BASIC_TIMEOUT), tcp_state, true);

                    conn.state.last_recvd = seq_num;
                    conn.state.last_recvd += 1;

                    tcph.GetWinSize(conn.state.rwnd);

                    MinetSend(mux, Create_Packet(conn, Buffer(), SYN_ACK, conn.state.last_sent));



                    conn.state.last_sent += 1;

                    cerr << "conn.state.last_sent:" << conn.state.last_sent << endl;

                    clist.push_front(conn);
                  }
              }

              break;
            case SYN_SENT :
                // CLIENT !!!
                // after client send the first SYN and wait
                // if got ACK -> go to established
                {
                    cerr << " In SYN_SENT" << endl;
                    if (IS_SYN(flags) && IS_ACK(flags)) {

                        cs->state.last_recvd = seq_num;
                        cs->state.last_recvd += 1;


                        tcph.GetWinSize(cs->state.rwnd);
                        //cs->timeout = Time(-1);
                        //TODO: window size
                        //cerr << "cs->state.last_sent:" << cs->state.last_sent <<endl;

                        MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));

                        cs->state.SetState(ESTABLISHED);

                        MinetSend(sock, SockRequestResponse(WRITE, cs->connection, Buffer(), 0, EOK));
                    }
                }
                break;
            case SYN_RCVD :
              // Wait for the second ACK
              // go to ESTABLISHED
              // If RST received
              // Reset to LISTEN
              {
                  cerr << "In SYN_RCVD" << endl;
                  if (IS_ACK(flags) && ack_num == cs->state.last_sent) {
                      cs->state.SetState(ESTABLISHED);
                      MinetSend(sock, SockRequestResponse(WRITE, cs->connection, Buffer(), 0, EOK));
                  } else {
                        cerr << "IS_ACK(flags) && ack_num eq == false"<< endl;
                  }
              }
              break;
            case ESTABLISHED :
              // If pkt_len != 0 -> receive data
              // Check ACK
              // Check FIN -> goto FIN
              {
                  cerr << "In Established" <<endl;
                  if (IS_FIN(flags)) {
                    cs->state.last_recvd += 1;

                    MinetSend(mux, Create_Packet(*cs, Buffer(), FIN, cs->state.last_sent));

                    cerr << "cs->state.last_sent" << cs->state.last_sent << endl;

                    cs->timeout = Time() + Time(BASIC_TIMEOUT);
                    cs->state.last_sent += 1;
                    cs->state.SetState(LAST_ACK);
                  }

                  if (data.GetSize() > 0) {
                    cerr << "In data received" << endl;
                    cs->state.last_recvd += data.GetSize();
                    MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));
                    MinetSend(sock, SockRequestResponse(WRITE, cs->connection, data, data.GetSize(), EOK));
                  }
              }
              break;
            case SEND_DATA :
              // No use in GO-back-N state machine
              break;
            case FIN_WAIT1:
              // Client Send the First FIN, and wait for ACK FIN2
              // If ACK -> goto FIN_WAIT2
              // IF FIN2 -> goto CLOSING
              {
                  cerr << "In FIN_WAIT1" << endl;
                  if (IS_FIN(flags) && ack_num != cs->state.last_sent){
                      // Got FIN2, but FIN1 doesn't ack
                      cs->state.last_recvd += 1;

                      MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));
                      cs->state.SetState(CLOSING);
                  } else if (IS_FIN(flags) && ack_num == cs->state.last_sent){
                      // Got FIN2, Got ACK for FIN1
                      cs->state.last_recvd += 1;

                      MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));
                      cs->state.SetState(TIME_WAIT);
                      cs->timeout = Time() + Time(BASIC_TIMEOUT);

                  } else if (IS_FIN(flags) == false && ack_num == cs->state.last_sent){
                     // Doesn't get FIN2, Got ACK for FIN1
                     cs->state.SetState(FIN_WAIT2);
                  }
              }
              break;
            case FIN_WAIT2:
              {
                 cerr << "In FIN_WAIT2" << endl;
                 if (IS_FIN(flags)){
                      cs->state.last_recvd += 1;

                      MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));
                      cs->state.SetState(TIME_WAIT);
                      cs->timeout = Time() + Time(BASIC_TIMEOUT);
                 }
              }
              break;
            case CLOSING:
              // Wait fo ACK of FIN1
              // goto TIME-WAIT
              {
                  cerr << "In CLOSING" << endl;
                  if (IS_ACK(flags) && ack_num == cs->state.last_sent) {
                    cs->state.SetState(TIME_WAIT);
                    cs->timeout = Time() + Time(BASIC_TIMEOUT);
                  }
              }
              break;
            case CLOSE_WAIT :
              //TODO skip this part.
              //FIN is sent by ESTABLISHED;
              break;
            case LAST_ACK:
              // wait for ACK of FIN2
              // goto CLOSED
              {
                 cerr << "In LAST_ACK, CLOSE the Sock" <<endl;

                 if (IS_ACK(flags) && ack_num == cs->state.last_sent) {
                     cs->state.SetState(CLOSED);
                 }


                 MinetSend(sock, SockRequestResponse(CLOSE, cs->connection, Buffer(), 0, EOK));
                 clist.erase(cs);

              }
              break;
            case TIME_WAIT:
              // IF duplicate FIN2 reveived
              // goto TIME-WAIT
              {
                  cerr << "In TIME_WAIT" << endl;
                  MinetSend(mux, Create_Packet(*cs, Buffer(), ACK, cs->state.last_sent));
                  cs->timeout = Time() + Time(BASIC_TIMEOUT);
              }
              break;
            default:
              cerr << "impossible" << endl;
          }
        } else {
          cerr << "cs == clist.end(), Not a connection we are interested." << endl;
          send_no_connection_error(iph, p, mux);
        }
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        cerr <<"got a message from sock" << endl;
        SockRequestResponse s;
        Packet p;
        MinetReceive(sock,s);

        switch (s.type) {
          case CONNECT :
            //create a connection
            //add conncetion to list
            // send fist SYN
            // goto SYN_SENT
            {
                cerr << "s.type == CONNECT" << endl;
                TCPState tcp_state(0, SYN_SENT, DEFAULT_Timertries); //seq_num, state, timertries
                ConnectionToStateMapping<TCPState>
                  conn(s.connection, Time() + Time(BASIC_TIMEOUT), tcp_state, true);

                cerr<< s.connection << endl;

                //@TODO: if conn exist in clist, erase it.


                MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EOK));

                Packet p = Create_Packet(conn, Buffer(), SYN, tcp_state.last_sent);
                conn.state.last_sent += 1;
                conn.state.last_recvd = 0;

                clist.push_front(conn);

                MinetSend(mux, p);
            }
            break;
          case ACCEPT :
            // SERVER !!
            // create a connection
            // goto LINSTEN
            {

                ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
                if (cs != clist.end()) break;

                TCPState tcp_state(0, LISTEN, DEFAULT_Timertries);
                ConnectionToStateMapping<TCPState>
                      conn(s.connection, Time() + Time(3600), tcp_state, true);
                conn.state.last_recvd = 0;
                clist.push_front(conn);

                cerr<< "ACCEPT: s.connection : " << s.connection << endl;


                SockRequestResponse srr;
                srr.type = STATUS;
                srr.error = EOK;
                MinetSend(sock, srr);
            }
            break;

          case WRITE:
            {
                ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
                if (cs!=clist.end() && cs->state.GetState() == ESTABLISHED) {

                  cs->state.SendBuffer.AddBack(Buffer(s.data));
                  // Warning: remove the following line!!! Only for test !!!
                  // cs->state.N = TCP_MAXIMUM_SEGMENT_SIZE * 3;

                  // cerr << "s.data.size" <<s.data.GetSize() << " " << s.data <<endl;
                  unsigned int packet_on_the_fly = cs->state.last_sent - cs->state.last_acked;
                  unsigned int packet_can_sent = cs->state.N - packet_on_the_fly;
                  unsigned int offset = packet_on_the_fly;

                  while (offset < cs->state.SendBuffer.GetSize() && offset < cs->state.N){

                    size_t size = TCP_MAXIMUM_SEGMENT_SIZE;

                    if (cs->state.SendBuffer.GetSize() - offset < size) size = cs->state.SendBuffer.GetSize() - offset;

                    char send_data[TCP_MAXIMUM_SEGMENT_SIZE + 50];
                    cs->state.SendBuffer.GetData(send_data, size, offset);

                    cerr << "Buffer :" << cs->state.SendBuffer << endl;

                    cerr << "Buffer Size:" << cs->state.SendBuffer.GetSize() << " offset :" << offset << " last_sent :" << cs->state.last_sent << " last_acked :" << cs->state.last_acked << " size :" << size << endl;
                    cerr << "Send Buffer:" << send_data << endl;

                    MinetSend(mux, Create_Packet(*cs, Buffer(send_data, size), ACK, cs->state.last_sent));

                    offset += size;
                    cs->state.last_sent += size;
                  }

                  cs->timeout = Time() + Time(BASIC_TIMEOUT);
                  MinetSend(sock, SockRequestResponse(STATUS, s.connection, Buffer(), 0, EOK));

                }

            }
            break;

          case FORWARD:
            {
                SockRequestResponse srr;
                srr.type = STATUS;
                srr.error = EOK;
                MinetSend(sock, srr);
            }
            break;

          case CLOSE:
            //I want to send Frsit FYN
            // goto FIN-WAIT-1
            {
                cerr << "In CLOSE from Sock" << endl;
                ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
                if (cs != clist.end()){
                    MinetSend(mux, Create_Packet(*cs, Buffer(), FIN, cs->state.last_sent));

                    cs->timeout = Time() + Time(BASIC_TIMEOUT);
                    cs->state.SetState(FIN_WAIT1);
                    cs->state.last_sent += 1;

                }
            }
            break;
          case STATUS:{
                ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
                if (cs!=clist.end() && cs->state.GetState() == ESTABLISHED) {
                  if (cs->state.RecvBuffer.GetSize() > 0){
                    //TODO, which buffer should use here?
                    MinetSend(sock, SockRequestResponse(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK));
                  }
                }
            }
            break;
        }

      }
    }
  }
  return 0;
}
