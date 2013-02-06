How-To run the voting process:

1. Run class de.uni.trier.infsec.functionalities.pki.real.PKIServer
This starts the public key environment which is needed for registration and lookup of public and verification keys.
The PKIServer stores the registered keys at %TEMP%/evoting_server.db - if you want to delete registered keys, you큞l have to delete this file.

2. Run class de.uni.trier.infsec.protocols.smt_voting.ServerRegisterStandalone
This will run the servers registration process. Server will register it큦 keys at the PKI environment and store the serialized keys to folder %TEMP%/smtvote

3. Run class de.uni.trier.infsec.protocols.smt_voting.ServerStandalone
The server will read the stored credentials and start listening for votes

4. Run class de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRegisterStandalone
This will run the bulletin boards registration process. It will register it큦 keys at the PKI environment and store the serialized keys to folder %TEMP%/smtvote

5. Run class de.uni.trier.infsec.protocols.smt_voting.BulletinBoardStandalone
This will run the bulletin board. It will keep listening for messages from the server and for requests for its content

6.1. In order to do a vote, you first have to register the voter by running class de.uni.trier.infsec.protocols.smt_voting.VoterRegisterStandalone with parameter <voter-id> which is expected as number in range 0 to 49
After registration is finished, the generated keys get stored to folder %TEMP%/smtvote

6.2. For sending the vote to the server, the voter has to be registered (6.1) and the credential is expected to be stored in the folder %TEMP%/smtvote
To vote, run class de.uni.trier.infsec.protocols.smt_voting.VoterVoteStandalone with parameters <vote> <voter-id>
Here the vote is expected as a two-digit HEX string 00 or 01, the ID is expected as number in range 0 to 49

After all votes have been cast, the server automatically posts it큦 content and the result to the bulletin board and terminates.

7. By running class de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRequestTool, the bulletin board will send its content and the request tool will print this content as hex to the shell.



EXAMPLE:
========

Run following commands from bin-folder of the compiled project:

1. java -cp ".;../lib/*" de.uni.trier.infsec.functionalities.pki.real.PKIServer
2. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.ServerRegisterStandalone
3. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.ServerStandalone
4. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRegisterStandalone
5. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.BulletinBoardStandalone

6.1. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.VoterRegisterStandalone 0
6.2. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.VoterVoteStandalone 01 0

7. java -cp ".;../lib/*" de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRequestTool

In order to delete the PKIServers persistent key database, delete the file %TEMP%/evoting_server.db