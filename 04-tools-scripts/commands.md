Parse file to read in a better way a SQL query from wireshark pcap using tshark

**tshark -r capture.pcap -Y "mysql.command==3" -T fields -e mysql.query**


TShark to filter out the User-Agent strings by using the following command:

**tshark --Y http.request -T fields -e http.host -e http.user\_agent -r analysis\_file.pcap**

