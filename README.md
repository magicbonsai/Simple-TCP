## Project 2 ##
name        netID   email
Kaiyu Hou   khh8084 kaiyuhou2022@u.northwestern.edu
Alex Zhu    azz970  alexanderzhu2017@u.northwestern.edu

## What we have done

- Three times handshake from both client and server side
- Successful closing connection from both client and server side
- Echo'ing text works from client and server
- run "tcp_server u <port>" accepts nc connection and accepts print data and close from nc client
- run "tcp_client u <address> <port>" connects to nc server and nc servers receives print data and CTRL-D close from tcp_client
- run "http_server1 u <port>" accpets telnet connection from client and "GET /TODO HTTP/1.0" grabs whole file successfully
- Timer - can retransmit first packet which always dropped due to bug in Minet

## TODO

- Support multiple connections but due to bug in Minet not feasible
- Send CLOSE to socket due to bug in Minet does not close Minet stack
